/* packet-iccp.c
 *
 * Wireshark ICCP / TASE.2 dissector plugin
 * IEC 60870-6 Inter-Control Center Communications Protocol
 *
 * This is a post-dissector layered on top of Wireshark's MMS (ISO 9506)
 * dissector. It adds ICCP/TASE.2 semantics that MMS alone does not know
 * about -- specifically:
 *
 *   - Association detection and naming (Phase 1)
 *   - MMS operation classification in the context of an ICCP flow
 *     (Read / Write / InformationReport / DefineNVL / ... -- Phase 2)
 *   - Conformance-Block classification of reserved object names:
 *     Block 1 Bilateral_Table, Block 2 DSConditions/Transfer Set,
 *     Block 3 Information_Message, Block 4 Program, Block 5 Device
 *     control, Block 6 Event, Block 7 Account, Block 8 Time Series,
 *     Block 9 extended error codes (Phase 1+4)
 *   - Device Control state tracking: SBO Select -> Operate, flag an
 *     Operate without a preceding Select (Phase 3)
 *
 * Important implementation notes, hard-won:
 *
 *   1. Post-dissectors that read other protocols' fields MUST call
 *      set_postdissector_wanted_hfids() at handoff, otherwise the tree
 *      optimizer elides those fields when tshark runs without -V and our
 *      scans see nothing.
 *
 *   2. Wireshark 4.2's proto_find_first_finfo() has persistent/stale
 *      behavior -- it can return non-NULL on packets where the field is
 *      not actually present. Use proto_get_finfo_ptr_array() instead;
 *      that reads the ref-array the tree optimizer maintains and is
 *      accurate per-packet.
 *
 *   3. In a domain-specific ObjectName, the variable name lives in
 *      mms.itemId, not in mms.Identifier. The latter is a named-type
 *      base rarely populated in practice.
 *
 *   4. mms.read_element / mms.write_element appear in both the request
 *      and the response PDU (they are the ConfirmedServiceRequest /
 *      ConfirmedServiceResponse CHOICE alternative). Distinguish by
 *      the presence of mms.confirmed_RequestPDU_element vs
 *      mms.confirmed_ResponsePDU_element.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_BUILD_DLL
#include <wireshark.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/ftypes/ftypes.h>
#include <epan/address_types.h>
#include <epan/to_str.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>
#include <wsutil/wmem/wmem_map.h>
#include <wsutil/wmem/wmem_array.h>
#include <epan/uat.h>
#include <epan/export_object.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/epan_dissect.h>
#include <epan/exceptions.h>

/* uat_add_record is exported from libwireshark but its prototype lives
 * in epan/uat-int.h which plugins should not depend on. Declare it
 * locally with the same signature. Stable across Wireshark 3.x/4.x. */
extern void *uat_add_record(uat_t *uat, const void *orig_rec_ptr, bool valid_rec);

/* Per-frame "already processed" flag key for p_add_proto_data. Used to
 * de-duplicate when a frame would otherwise hit both the OID-level
 * wrapper (during dissection) and the post-dissector (after dissection). */
#define ICCP_PFRAME_DONE_KEY 0xCAFEBABEu

/* Per-frame "tap already queued" flag key. Distinct from PFRAME_DONE_KEY
 * because dissect_iccp can run (and add proto-tree subtrees) via both
 * the OID-level wrapper and the post-dissector fallback. The flag
 * prevents multiple call-sites from queueing the same frame (which
 * would double every count axis). */
#define ICCP_TAP_QUEUED_KEY  0xCAFEBABFu

/* File-scoped key that persists the tap_info across retaps.
 * On the first pass (when MMS fully dissects), iccp_emit_tap stores the
 * tap data here. On retap, COTP/Session reassembly often fails for
 * multi-segment packets, so MMS produces a partial/malformed tree.
 * By re-queuing the saved first-pass data, the stats callback always
 * sees correct values. */
#define ICCP_TAP_SAVED_KEY   0xCAFEBAC0u
/* Per-frame guard for the DefineNVL parse + auto-DSD map population
 * + Export Objects tap queue inside iccp_dsd_capture(). Without this,
 * every retap (stats Apply / dialog reopen / -z run) re-parses the
 * same DefineNVL bytes, allocates new wmem_file_scope strings + key
 * + variable-name array, overwrites the previous entry in the auto
 * map, and pushes a duplicate row into File -> Export Objects -> ICCP.
 * Codex flagged this in the v0.8 design review -- distinct from
 * ICCP_TAP_QUEUED_KEY because Define-NVL parsing happens before the
 * regular tap is queued and is gated on a different precondition. */
#define ICCP_DSD_CAPTURED_KEY 0xCAFEBAC1u

/* Set at handoff. NULL if MMS isn't loaded into Wireshark (very rare). */
static dissector_handle_t mms_handle = NULL;

/* Forward decl: the wrapper that lives above dissect_iccp in this file
 * calls dissect_iccp directly, so the compiler needs the prototype. */
static int dissect_iccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

#include <string.h>

#include "packet-iccp.h"

/* -------------------------------------------------------------------------
 * Registration state
 * ---------------------------------------------------------------------- */

static int proto_iccp = -1;

static int hf_iccp_association_state = -1;
static int hf_iccp_object_category   = -1;
static int hf_iccp_object_name       = -1;
static int hf_iccp_scope             = -1;  /* "VCC" or "Bilateral" */
static int hf_iccp_domain            = -1;  /* Bilateral Table id when scope=Bilateral */
static int hf_iccp_operation         = -1;
static int hf_iccp_conformance_block = -1;
static int hf_iccp_device_state      = -1;
static int hf_iccp_note              = -1;

/* Report-payload summary fields, populated on InformationReport /
 * Read-Response PDUs. */
static int hf_iccp_report_points     = -1;
static int hf_iccp_report_success    = -1;
static int hf_iccp_report_failure    = -1;
static int hf_iccp_report_structured = -1;
static int hf_iccp_report_summary    = -1;

/* MMS floating-point primitive decoded to a real number. Wireshark's
 * MMS dissector renders these as raw bytes (e.g. "08be81a9a0") because
 * the 1-byte-exponent-width prefix is non-standard outside MMS. We
 * decode them here. */
static int hf_iccp_value_real        = -1;

/* TASE.2 IndicationPoint quality (per IEC 60870-6-802 §8.2.1, the
 * Object Models companion to IEC 60870-6-503). Encoded as a 1-byte
 * BIT STRING in MMS:
 *   bits 7-6  validity         00=VALID 01=HELD 10=SUSPECT 11=NOT_VALID
 *   bit  5    NormalValue      1=NORMAL 0=OFF_NORMAL  (per spec, NOT inverted)
 *   bit  4    timestamp_qual   0=VALID  1=INVALID
 *   bits 3-2  current_source   00=TELEMETERED  01=CALCULATED
 *                              10=ENTERED      11=ESTIMATED
 *   bits 1-0  reserved
 * Each subfield is exposed as its own filterable hf so users can
 * graph or filter individual flags; iccp.quality is the raw byte for
 * the bitmask child rendering, iccp.quality.summary is a one-line
 * human-friendly digest like "VALID/TELEMETERED/NORMAL/TS_OK". */
static int hf_iccp_quality           = -1;
static int hf_iccp_quality_validity  = -1;
static int hf_iccp_quality_normal    = -1;
static int hf_iccp_quality_ts_invalid = -1;
static int hf_iccp_quality_source    = -1;
static int hf_iccp_quality_summary   = -1;

/* Combined-point row: a TASE.2 IndicationPoint typically materialises
 * as a structure of (floating-point, bit-string) -- value plus
 * quality. We synthesise an "iccp.point" item that puts both on a
 * single line so a 250-point report becomes 250 readable rows
 * instead of 1000 raw-hex sub-leaves. */
static int hf_iccp_point_summary               = -1;
static int hf_iccp_point_value                 = -1;
static int hf_iccp_point_quality               = -1;
static int hf_iccp_point_index                 = -1;
static int hf_iccp_point_slot                  = -1;
static int hf_iccp_point_name                  = -1;
static int hf_iccp_point_timestamp             = -1;
static int hf_iccp_point_timestamp_ms_extended = -1;
static int hf_iccp_point_timestamp_age         = -1;
static int hf_iccp_point_state                 = -1;
static int hf_iccp_point_state_supplemental    = -1;
static int hf_iccp_point_discrete              = -1;
/* Per-PDU TASE.2 Transfer_Set_Time_Stamp -- wall-clock UTC the source
 * RTU assigned to the report at assembly time. Encoded on the wire as
 * a 4-byte MMS INTEGER (Data CHOICE alt [5] IMPLICIT, tag 0x85) at the
 * slot whose DSD-resolved variable name is "Transfer_Set_Time_Stamp"
 * (typically slot 1). One timestamp per report, applied to every
 * point unless a per-point BinaryTime overrides it. */
static int hf_iccp_transfer_set_timestamp      = -1;
static int hf_iccp_transfer_set_timestamp_slot = -1;

/* Forward declaration: the user-supplied DSD-mapping UAT lives further
 * down in the file (next to its registration in proto_register_iccp);
 * dissect_iccp calls iccp_dsd_lookup from the recovered-points subtree
 * builder. */
static const char *iccp_dsd_lookup(const char *domain,
                                   const char *transfer_set,
                                   guint32 slot);
static void        iccp_dsd_capture(tvbuff_t *tvb, packet_info *pinfo);
static void        iccp_dsd_auto_reset(void);

/* Payload queued on the Export Objects tap for File -> Export Objects ->
 * ICCP. One queued event per DefineNamedVariableList-Request frame that
 * iccp_dsd_capture parsed successfully. Strings live in wmem_file_scope
 * (same allocator as iccp_dsd_auto), so the tap callback must g_strdup
 * before handing anything to export_object_entry_t (Wireshark frees the
 * entry via g_free, not via the wmem allocator). */
typedef struct {
    guint32       pkt_num;
    const char   *domain;       /* may be NULL or "" for VMD-scope lists */
    const char   *list_name;    /* always non-NULL when queued */
    guint         slot_count;
    char        **slot_names;   /* slot_count cstrings, in slot order */
} iccp_dsd_tap_info_t;

static int iccp_dsd_eo_tap = -1;
static gboolean    iccp_ber_read_object_name(const guint8 **p,
                                             const guint8 *end,
                                             wmem_allocator_t *scope,
                                             char **domain_out,
                                             char **item_out);

static gint ett_iccp         = -1;
static gint ett_iccp_objects = -1;
static gint ett_iccp_device  = -1;
static gint ett_iccp_value   = -1;
static gint ett_iccp_quality = -1;
static gint ett_iccp_point   = -1;

static expert_field ei_iccp_association_seen   = EI_INIT;
static expert_field ei_iccp_object_seen        = EI_INIT;
static expert_field ei_iccp_info_report        = EI_INIT;
static expert_field ei_iccp_device_operate     = EI_INIT;
static expert_field ei_iccp_device_no_select   = EI_INIT;
static expert_field ei_iccp_device_stale_sel   = EI_INIT;

static dissector_handle_t iccp_handle;
static int proto_iccp_tap = -1;

/* Stats tree identifiers (one -z menu per axis of analysis). */
static int st_node_ops        = -1;
static int st_node_categories = -1;
static int st_node_blocks     = -1;
static int st_node_assocs     = -1;
static int st_node_devices    = -1;
static int st_node_reports    = -1;
static int st_node_points_set    = -1;  /* Tier 3: pivot per Transfer-Set (count) */
static int st_node_points_qual   = -1;  /* Tier 3: validity-class breakdown (count) */
static int st_node_points_source = -1;  /* Tier 3: CurrentSource breakdown (count) */
static int st_node_points_range  = -1;  /* Tier 3: value range buckets (count) */
static int st_node_peers         = -1;  /* Tier 5: per src->dst peer pivot (count) */
static int st_node_scope         = -1;  /* TASE.2 name scope (VCC vs Bilateral) (count) */
/* Tier 4 axes -- STAT_DT_FLOAT, populate the Average/Min/Max columns
 * in the Wireshark stats dialog. Built per-point or per-PDU value
 * distributions on top of the same iccp_tap_info_t the count axes use. */
static int st_node_pvalues          = -1;  /* per-point: every numeric value */
static int st_node_pvalues_qual     = -1;  /* per-point: by validity class */
static int st_node_pvalues_set      = -1;  /* per-point: by Transfer Set */
static int st_node_pvalues_cb       = -1;  /* per-point: by Conformance Block */
static int st_node_points_per_pdu   = -1;  /* per-PDU:  point_count distribution */
static int st_node_success_ratio    = -1;  /* per-PDU:  AccessResult success ratio */
static int st_node_quality_mix      = -1;  /* per-PDU:  validity-class fractions */
static int st_node_pdu_sizes        = -1;  /* per-PDU:  frame length, with per-Op breakdown */
/* Opt-in (preference iccp.stats_per_point_name): per-point-name leaves
 * nested under each Transfer Set. Default off because Statkraft-scale
 * captures (thousands of distinct slot names) can slow stats retap. */
static int st_node_points_byname    = -1;  /* count tree:  TransferSet -> point name -> tick */
static int st_node_pvalues_byname   = -1;  /* float tree:  TransferSet -> point name -> avg/min/max */

/* Bool preference: when TRUE, populate the per-point-name leaves above. */
static gboolean iccp_pref_stats_per_point_name = FALSE;

/* Tap payload: everything a listener (stats_tree, custom Lua tap, an
 * external analysis) might reasonably want to know about a single ICCP
 * packet. Allocated from wmem_file_scope() and saved via per-frame proto
 * data (ICCP_TAP_SAVED_KEY) so the same data is re-queued on retap.
 * String fields point to either static literals or wmem_file_scope()
 * copies; per-point arrays are also in file scope. */
typedef struct {
    int            op;             /* iccp_op_t */
    const char    *op_str;
    int            assoc_state;    /* iccp_assoc_state_t */
    guint8         cb;             /* 0 if no ICCP category match */
    const char    *object_category;
    const char    *object_name;
    const char    *device_name;
    int            device_state;   /* iccp_dev_state_t, valid iff device_name != NULL */
    const char    *device_sub;     /* Select / SBO-Operate / Direct-Operate / Cancel / Tag / ... */
    /* Report accounting (0 on PDUs that are not Read-Response /
     * InformationReport / Write-Response). */
    guint32        report_points;
    guint32        report_success;
    guint32        report_failure;
    gboolean       report_structured;

    /* Per-point synthesis accounting (Tier 3). Populated by the
     * post-dissector's attach_decoded_values walker for any PDU that
     * yields synthesised iccp.point rows. set_name names the
     * Transfer-Set / variable list the points belong to (or NULL on
     * unnamed objects -- e.g. heavily anonymised captures); the four
     * quality counters are tallies of TASE.2 IndicationPoint quality
     * codes seen in this PDU; the value range carries min/max/sum so
     * stats listeners can compute means without reparsing. */
    const char    *set_name;
    const char    *scope;       /* "VCC" / "Bilateral" / NULL */
    const char    *domain_id;   /* Bilateral Table id when scope=Bilateral */
    guint32        point_count;
    guint32        points_valid;
    guint32        points_held;
    guint32        points_suspect;
    guint32        points_notvalid;
    /* CurrentSource histogram per IEC 60870-6-802 §8.2.1. */
    guint32        points_telemetered;
    guint32        points_calculated;
    guint32        points_entered;
    guint32        points_estimated;
    gfloat         point_value_min;
    gfloat         point_value_max;
    gfloat         point_value_sum;
    gboolean       has_point_values;
    /* Per-point detail for STAT_DT_FLOAT axes. Same allocation pool as
     * the surrounding tap_info, valid only inside the tap-listener call
     * (listeners that retain it across packets must copy). NULL if no
     * points were synthesised. point_validities[i] is in 0..3 mapping
     * to VALID/HELD/SUSPECT/NOT_VALID. */
    wmem_array_t  *point_values_arr;
    wmem_array_t  *point_validities_arr;
    /* Parallel to point_values_arr when populated by the BER walker
     * (one slot index per numeric point). May be shorter than
     * point_values_arr when the proto-tree walker dominated (it doesn't
     * track slots) -- consumers must check the array lengths agree
     * before indexing in lock-step. */
    wmem_array_t  *point_slots_arr;
} iccp_tap_info_t;

/* We do not cache MMS hf indices: walk_tree() matches fields by
 * hfinfo->abbrev because asn2wrs registers duplicate hfs for the same
 * abbrev (see walk_tree() comment). At handoff we still need to mark
 * every duplicate as "wanted" for the tree optimizer -- that happens
 * by scanning the MMS protocol's registered fields once, matching by
 * abbrev, and passing all matching hfids to set_postdissector_wanted_hfids. */

/* -------------------------------------------------------------------------
 * TASE.2 / ICCP name patterns
 *
 * From IEC 60870-6-503 and the TASE.2 Object Model. Token is a
 * case-sensitive substring; the first match wins (order matters --
 * more specific patterns come first).
 * ---------------------------------------------------------------------- */

/* IEC 60870-6-503 TASE.2 IndicationPoint quality flag bit definitions. */
#define ICCP_Q_VALIDITY_MASK    0xC0
#define ICCP_Q_NORMAL_MASK      0x20
#define ICCP_Q_TS_INVALID_MASK  0x10
#define ICCP_Q_SOURCE_MASK      0x0C

static const value_string iccp_q_validity_vals[] = {
    { 0, "VALID" },
    { 1, "HELD" },
    { 2, "SUSPECT" },
    { 3, "NOT_VALID" },
    { 0, NULL }
};

/* CurrentSource per IEC 60870-6-802 (TASE.2 Object Models) section 8.2.1.
 * The 2-bit field encodes how the value was acquired by the source
 * RTU / control center -- operationally critical because it tells you
 * whether you're looking at a real telemetered measurement or a
 * filled-in estimate.
 *
 * Earlier code used DNP3-style labels (CURRENT/HELD/SUBSTITUTED/GARBLED)
 * that don't match TASE.2 spec; corrected to the canonical names.
 * The bit values themselves are unchanged, so any saved display filter
 * referencing iccp.quality.source by integer (e.g. == 0) still works;
 * filters that referenced the OLD string names ("CURRENT" etc.) need
 * to be updated to the new ones. */
static const value_string iccp_q_source_vals[] = {
    { 0, "TELEMETERED" },  /* came from a real telemetry channel */
    { 1, "CALCULATED"  },  /* derived/computed from other measurements */
    { 2, "ENTERED"     },  /* manually keyed in by an operator */
    { 3, "ESTIMATED"   },  /* system filled in (real value unavailable) */
    { 0, NULL }
};

/* Build a one-line "VALID/CURRENT/NORMAL/TS_OK" summary out of a
 * raw quality byte. Returns a static-buffered string (caller should
 * not retain across calls). */
static const char *
iccp_quality_summary(char *buf, size_t buflen, guint8 q)
{
    const char *valid  = val_to_str_const((q & ICCP_Q_VALIDITY_MASK) >> 6,
                                          iccp_q_validity_vals, "?");
    const char *source = val_to_str_const((q & ICCP_Q_SOURCE_MASK)   >> 2,
                                          iccp_q_source_vals,   "?");
    /* NormalValue per IEC 60870-6-802 §8.2.1: bit set => point IS in
     * its normal operating range. Earlier code had the sense inverted
     * (showing OFF_NORMAL for healthy points and NORMAL for alarming
     * ones), which is the opposite of every TASE.2 reference and
     * conflicts with what SCADA HMIs actually do with this bit. */
    const char *normal = (q & ICCP_Q_NORMAL_MASK)     ? "NORMAL" : "OFF_NORMAL";
    const char *tsq    = (q & ICCP_Q_TS_INVALID_MASK) ? "TS_INVALID" : "TS_OK";
    g_snprintf(buf, buflen, "%s / %s / %s / %s", valid, source, normal, tsq);
    return buf;
}

typedef struct {
    const char *token;
    const char *category;
    guint8      cb;
} iccp_name_pattern_t;

static const iccp_name_pattern_t iccp_name_patterns[] = {
    /* Block 5 - Device Control suffixes. Order matters: more specific
     * patterns come first so we classify "TagOperate" before the generic
     * "Operate" substring hits. */
    { "SBOSelect",              "Device Select-Before-Operate",   5 },
    { "SBOOperate",             "Device SBO Operate",             5 },
    { "TagOperate",             "Device Tag Operate",             5 },
    { "ExecutionCommand",       "Device Execution Command",       5 },
    { "CheckBack",              "Device Checkback",               5 },
    { "Operate",                "Device Direct Operate",          5 },
    { "Cancel",                 "Device Cancel",                  5 },

    /* Block 1 - Basic services */
    { "Bilateral_Table",        "Bilateral Table",                1 },
    { "TASE2_Version",          "Version object",                 1 },
    { "Supported_Features",     "Supported Features",             1 },
    { "DSName_",                "Data Set Name",                  1 },

    /* Block 2 - Extended Data Set Condition Monitoring */
    { "DSConditions_",          "DSConditions Transfer Set",      2 },
    { "DSTransfer_Set_",        "DS Transfer Set",                2 },
    { "Next_DSTransfer_Set",    "DS Transfer Set (next)",         2 },
    { "Transfer_Set_",          "Transfer Set",                   2 },
    { "Transfer_Report_Name",   "Transfer Report",                2 },
    { "Transfer_Account",       "Transfer Account",               2 },
    { "Transfer_Conditions_Detected", "Transfer Conditions",      2 },

    /* Block 3 - Information Messages */
    { "Information_Message_",   "Information Message",            3 },
    { "Info_Buffer_",           "Info Buffer",                    3 },
    { "Info_Message_",          "Information Message",            3 },

    /* Block 4 - Program Control */
    { "Program_",               "Program",                        4 },

    /* Block 5 - Device control (fallback) */
    { "Device_",                "Device",                         5 },
    { "Control_",               "Control object",                 5 },

    /* Block 6 - Events */
    { "Event_Condition_",       "Event Condition",                6 },
    { "Event_Enrollment_",      "Event Enrollment",               6 },
    { "Event_Action_",          "Event Action",                   6 },

    /* Block 7 - Account Tracking */
    { "Account_",               "Account",                        7 },
    { "Operator_Account_",      "Operator Account",               7 },

    /* Block 8 - Time Series */
    { "DSTimeSeries_",          "DS Time Series",                 8 },
    { "TimeSeries_",            "Time Series",                    8 },
    { "Historical_Data_",       "Historical Data",                8 },

    /* Block 9 - Additional / error handling */
    { "Error_Log",              "Error Log",                      9 },
    { "Error_Code_",            "Error Code",                     9 },

    /* Heuristic patterns for utility-internal naming conventions that
     * don't match the canonical IEC 60870-6-503 reserved names. These
     * come AFTER the canonical patterns so a name that matches a
     * canonical token (DSConditions_, DSTransfer_Set_, DSTimeSeries_)
     * classifies under the canonical category, not the heuristic one.
     *
     * Real-world ICCP captures from electric utilities (EXAMPLE_UTIL_A,
     * EXAMPLE_UTIL_B, EXAMPLE_UTIL_C, etc. observed) overwhelmingly use names like
     *   DS_ANA_A_L_<utility>          analog point dataset
     *   DS_DIG_X_Y_<utility>          digital point dataset
     *   <utility>_MEA / *_MEA_1       measurement transfer set
     *   <utility>_<scope>_CYCLIC      cyclic transfer set
     *   R00L00DataSet0001DA98         vendor-internal dataset id
     * which all carry valid TASE.2 IndicationPoint payloads but
     * wouldn't otherwise classify. With these heuristic patterns the
     * Object category / Conformance Block axes light up and the
     * association lifecycle promotes to Confirmed ICCP. */
    { "DS_",                    "Data Set (heuristic)",            2 },
    { "DataSet",                "Data Set (heuristic)",            2 },
    { "_MEA",                   "Measurement Set (heuristic)",     2 },
    { "_CYCLIC",                "Cyclic Transfer Set (heuristic)", 2 },

    { NULL, NULL, 0 }
};

static const iccp_name_pattern_t *
iccp_classify_name(const char *name)
{
    if (!name || !*name)
        return NULL;
    for (const iccp_name_pattern_t *p = iccp_name_patterns; p->token; p++) {
        if (strstr(name, p->token) != NULL)
            return p;
    }
    return NULL;
}

/* Narrow Block 5 pattern to sub-operation (Select / Operate / Cancel / Tag).
 * Returns NULL for names that look like generic Device_*.
 */
static const char *
iccp_device_subop(const char *name)
{
    if (!name) return NULL;
    if (strstr(name, "SBOSelect"))        return "Select";
    if (strstr(name, "SBOOperate"))       return "SBO-Operate";
    if (strstr(name, "Cancel"))           return "Cancel";
    if (strstr(name, "TagOperate"))       return "Tag";
    if (strstr(name, "ExecutionCommand")) return "Execute";
    if (strstr(name, "CheckBack"))        return "Checkback";
    /* "Operate" alone means direct operate when not preceded by SBO. */
    if (strstr(name, "Operate"))          return "Direct-Operate";
    return NULL;
}

/* -------------------------------------------------------------------------
 * MMS operation classification
 * ---------------------------------------------------------------------- */

typedef enum {
    ICCP_OP_NONE = 0,
    ICCP_OP_ASSOC_REQ,
    ICCP_OP_ASSOC_RESP,
    ICCP_OP_CONCLUDE_REQ,
    ICCP_OP_CONCLUDE_RESP,
    ICCP_OP_REJECT,
    ICCP_OP_READ_REQ,
    ICCP_OP_READ_RESP,
    ICCP_OP_WRITE_REQ,
    ICCP_OP_WRITE_RESP,
    ICCP_OP_INFORMATION_REPORT,
    ICCP_OP_GET_NAMELIST_REQ,
    ICCP_OP_GET_NAMELIST_RESP,
    ICCP_OP_GET_VAR_ATTR_REQ,
    ICCP_OP_GET_VAR_ATTR_RESP,
    ICCP_OP_DEFINE_NVL_REQ,
    ICCP_OP_DEFINE_NVL_RESP,
    ICCP_OP_DELETE_NVL_REQ,
    ICCP_OP_DELETE_NVL_RESP,
    ICCP_OP_CONFIRMED_ERROR,
} iccp_op_t;

static const char *
iccp_op_str(iccp_op_t op)
{
    switch (op) {
    case ICCP_OP_ASSOC_REQ:            return "Associate-Request";
    case ICCP_OP_ASSOC_RESP:           return "Associate-Response";
    case ICCP_OP_CONCLUDE_REQ:         return "Conclude-Request";
    case ICCP_OP_CONCLUDE_RESP:        return "Conclude-Response";
    case ICCP_OP_REJECT:               return "Reject";
    case ICCP_OP_READ_REQ:             return "Read-Request";
    case ICCP_OP_READ_RESP:            return "Read-Response";
    case ICCP_OP_WRITE_REQ:            return "Write-Request";
    case ICCP_OP_WRITE_RESP:           return "Write-Response";
    case ICCP_OP_INFORMATION_REPORT:   return "InformationReport";
    case ICCP_OP_GET_NAMELIST_REQ:     return "GetNameList-Request";
    case ICCP_OP_GET_NAMELIST_RESP:    return "GetNameList-Response";
    case ICCP_OP_GET_VAR_ATTR_REQ:     return "GetVariableAccessAttributes-Request";
    case ICCP_OP_GET_VAR_ATTR_RESP:    return "GetVariableAccessAttributes-Response";
    case ICCP_OP_DEFINE_NVL_REQ:       return "DefineNamedVariableList-Request";
    case ICCP_OP_DEFINE_NVL_RESP:      return "DefineNamedVariableList-Response";
    case ICCP_OP_DELETE_NVL_REQ:       return "DeleteNamedVariableList-Request";
    case ICCP_OP_DELETE_NVL_RESP:      return "DeleteNamedVariableList-Response";
    case ICCP_OP_CONFIRMED_ERROR:      return "Confirmed-Error";
    default:                           return NULL;
    }
}

/* -------------------------------------------------------------------------
 * Per-conversation state
 * ---------------------------------------------------------------------- */

typedef enum {
    ICCP_ASSOC_NONE      = 0,
    ICCP_ASSOC_CANDIDATE = 1,
    ICCP_ASSOC_CONFIRMED = 2
} iccp_assoc_state_t;

typedef enum {
    ICCP_DEV_IDLE     = 0,
    ICCP_DEV_SELECTED = 1,
    ICCP_DEV_OPERATED = 2
} iccp_dev_state_t;

typedef struct iccp_device_entry {
    char             name[64]; /* device base name (prefix before SBO suffix) */
    char             server[64]; /* server endpoint as "addr:port" */
    iccp_dev_state_t state;
    guint32          select_frame;       /* frame in which Select was seen */
    guint32          select_conv_index;  /* conversation index where Select happened */
} iccp_device_entry_t;

typedef struct {
    iccp_assoc_state_t state;
    guint32            initiate_frame;
    guint32            confirmed_frame;
    char               confirmation_name[64];
    guint8             confirmation_cb;
} iccp_conv_t;

/* Cross-conversation device state: every device observed across the whole
 * capture, keyed by "<server_addr>:<server_port>#<device_base_name>".
 * Real ICCP SBO correlations happen on a single persistent association,
 * but some deployments split Select and Operate onto separate
 * associations to the same server -- this table makes that case
 * traceable. Stored in wmem_file_scope so it lives as long as the
 * capture file is open. Initialised lazily. */
static wmem_map_t *g_devices = NULL;

static iccp_conv_t *
iccp_conv_get(packet_info *pinfo, gboolean create)
{
    conversation_t *conv = find_or_create_conversation(pinfo);
    if (!conv)
        return NULL;
    iccp_conv_t *info = (iccp_conv_t *)conversation_get_proto_data(conv, proto_iccp);
    if (!info && create) {
        info = wmem_new0(wmem_file_scope(), iccp_conv_t);
        conversation_add_proto_data(conv, proto_iccp, info);
    }
    return info;
}

/* Identify the server side of the current packet's TCP flow. ICCP
 * servers listen on a well-known ISO-TSAP port (102, or a vendor
 * non-standard one), which is numerically smaller than the client's
 * ephemeral port. Pick the lower port as server. This is a heuristic
 * that is correct for every real ICCP capture the author has seen.
 * Writes "<addr>:<port>" into dst. */
static void
iccp_server_endpoint_str(packet_info *pinfo, char *dst, size_t buf_sz)
{
    const address *addr;
    guint32        port;
    if (pinfo->srcport < pinfo->destport) {
        addr = &pinfo->src;
        port = pinfo->srcport;
    } else {
        addr = &pinfo->dst;
        port = pinfo->destport;
    }
    const char *a = address_to_str(pinfo->pool, addr);
    g_snprintf(dst, buf_sz, "%s:%u", a ? a : "?", port);
}

/* Compose the hash key used in g_devices. */
static char *
iccp_device_key(wmem_allocator_t *scope, const char *server, const char *base)
{
    return wmem_strdup_printf(scope, "%s#%s", server, base);
}

/* Strip the ICCP control suffix from a device object name to get the
 * base device identity, e.g.
 *   "Device_Breaker_A.SBOSelect" -> "Device_Breaker_A"
 *   "Device_Line5_Operate"       -> "Device_Line5"
 * Writes into dst (buf_sz bytes). */
static void
iccp_device_base_name(const char *name, char *dst, size_t buf_sz)
{
    if (!name || !dst || !buf_sz) return;
    const char *suffixes[] = {
        ".SBOSelect", "_SBOSelect", ".SBOOperate", "_SBOOperate",
        ".Cancel", "_Cancel", ".TagOperate", "_TagOperate",
        ".ExecutionCommand", "_ExecutionCommand",
        ".CheckBack", "_CheckBack",
        ".Operate", "_Operate",
        NULL
    };
    size_t n = strlen(name);
    for (int i = 0; suffixes[i]; i++) {
        const char *s = suffixes[i];
        size_t slen = strlen(s);
        if (n >= slen && strcmp(name + n - slen, s) == 0) {
            size_t take = n - slen;
            if (take >= buf_sz) take = buf_sz - 1;
            memcpy(dst, name, take);
            dst[take] = '\0';
            return;
        }
    }
    g_strlcpy(dst, name, buf_sz);
}

static iccp_device_entry_t *
iccp_device_lookup(packet_info *pinfo, const char *base_name, gboolean create)
{
    if (!base_name) return NULL;

    if (!g_devices) {
        g_devices = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
    }

    char server[64];
    iccp_server_endpoint_str(pinfo, server, sizeof server);

    /* Use packet scope for the lookup key; use file scope only for the
     * stored key if we end up inserting. */
    char *lookup_key = iccp_device_key(pinfo->pool, server, base_name);

    iccp_device_entry_t *e = (iccp_device_entry_t *)wmem_map_lookup(g_devices, lookup_key);
    if (e || !create) return e;

    e = wmem_new0(wmem_file_scope(), iccp_device_entry_t);
    g_strlcpy(e->name,   base_name, sizeof e->name);
    g_strlcpy(e->server, server,    sizeof e->server);
    e->state = ICCP_DEV_IDLE;

    char *stored_key = iccp_device_key(wmem_file_scope(), server, base_name);
    wmem_map_insert(g_devices, stored_key, e);
    return e;
}

/* -------------------------------------------------------------------------
 * Tree walker
 *
 * In Wireshark 4.2 both "fast" APIs we tried had issues:
 *   - proto_find_first_finfo() walks the tree but has a persistent/stale
 *     behavior where it returns non-NULL on packets where the field is
 *     not present.
 *   - proto_get_finfo_ptr_array() reads a ref-array maintained by the
 *     tree optimizer. After set_postdissector_wanted_hfids() it is
 *     accurate for many fields, but some code paths in the ASN.1
 *     generator add items without updating the ref-array (we hit this
 *     on mms.read_element on confirmed-Request PDUs).
 *
 * The only bulletproof source of truth is proto_all_finfos(), which
 * returns every field_info actually in the current tree. We do ONE
 * pass per packet and populate all the flags and name collections we
 * need from the same walk.
 * ---------------------------------------------------------------------- */

typedef struct {
    gboolean has_initiate_req;
    gboolean has_initiate_resp;
    gboolean has_conclude_req;
    gboolean has_conclude_resp;
    gboolean has_reject;
    gboolean has_info_report;
    gboolean has_confirmed_req;
    gboolean has_confirmed_resp;
    gboolean has_confirmed_err;
    gboolean has_read;
    gboolean has_write;
    gboolean has_get_namelist;
    gboolean has_get_var_attr;
    gboolean has_define_nvl;
    gboolean has_delete_nvl;
    /* Report / typed-data accounting, populated for every packet the
     * MMS dissector decoded. These are counts of mms.* occurrences in
     * the tree; we use them to surface useful per-report summaries
     * under iccp.report.* on InformationReport / Read-Response PDUs. */
    guint32  access_result_count;
    guint32  success_count;
    guint32  failure_count;
    guint32  structure_count;
    guint32  floating_point_count;
    guint32  bit_string_count;
    guint32  binary_time_count;
    guint32  visible_string_count;
    guint32  octet_string_count;
    /* Diagnostic counters for MMS Data CHOICE alternatives our decoder
     * currently ignores. Surfaced in the "Report data summary" line so
     * we can see at a glance whether a vendor encodes timestamps as
     * UtcTime [17] / GeneralizedTime [11] / Real [8] / Bcd [13] etc.
     * Non-zero on any of these is a hint that we need to add per-point
     * decode for that alternative. */
    guint32  utc_time_count;          /* MMS Data utc-time [17] = 0x91 */
    guint32  generalized_time_count;  /* MMS Data generalized-time [11] = 0x8b */
    guint32  real_count;              /* MMS Data real [8] = 0x88 */
    guint32  bcd_count;               /* MMS Data bcd [13] = 0x8d */
    guint32  mms_string_count;        /* MMS Data mMSString [16] = 0x90 */
} iccp_pdu_flags_t;

/* TASE.2 name scope. A name in MMS lives either in the VMD's global
 * namespace (TASE.2 calls this VCC scope -- "public" inside this
 * control center) or inside a named domain (TASE.2 calls this
 * Bilateral / ICC scope -- the domain is typically the Bilateral
 * Table identifier the two peers agreed on). The scope distinction
 * matters operationally: bilateral writes (especially Device_*) are
 * the high-value targets; an unexpected VCC-scope access to a
 * Bilateral object is itself an anomaly. */
typedef enum {
    ICCP_SCOPE_NONE = 0,
    ICCP_SCOPE_VCC,
    ICCP_SCOPE_BILATERAL
} iccp_scope_t;

static const char *
iccp_scope_str(iccp_scope_t s)
{
    switch (s) {
        case ICCP_SCOPE_VCC:       return "VCC";
        case ICCP_SCOPE_BILATERAL: return "Bilateral";
        default:                   return NULL;
    }
}

typedef struct {
    const iccp_name_pattern_t *matched;
    const char                *matched_name;
    const char                *first_name;
    guint                      total;
    iccp_scope_t               scope;
    const char                *domain_id;   /* set when scope == BILATERAL */
} iccp_name_scan_t;

/* Classify a single identifier string; callback helper. */
static void
iccp_consider_name(iccp_name_scan_t *s, const char *name)
{
    if (!name || !*name) return;
    s->total++;
    if (!s->first_name)
        s->first_name = name;
    if (s->matched) return;
    const iccp_name_pattern_t *p = iccp_classify_name(name);
    if (p) {
        s->matched      = p;
        s->matched_name = name;
    }
}

/* Single tree walk: populate pdu flags, scan identifier strings.
 *
 * We match fields by hfinfo->abbrev, not by cached hf id. asn2wrs
 * generates duplicate abbrevs for CHOICE alternatives that appear at
 * multiple use sites (e.g. mms.read_element is registered twice, once
 * inside ConfirmedServiceRequest and once inside ConfirmedServiceResponse).
 * proto_registrar_get_id_byname() returns only the first match, so a
 * cached id misses the other use site entirely. strcmp-by-abbrev sees
 * both. */
static void
walk_tree(packet_info *pinfo _U_, proto_tree *tree,
          iccp_pdu_flags_t *flags, iccp_name_scan_t *scan)
{
    memset(flags, 0, sizeof *flags);
    memset(scan,  0, sizeof *scan);
    if (!tree) return;

    GPtrArray *all = proto_all_finfos(tree);
    if (!all) return;

    for (guint i = 0; i < all->len; i++) {
        field_info *fi = (field_info *)g_ptr_array_index(all, i);
        if (!fi || !fi->hfinfo || !fi->hfinfo->abbrev) continue;
        const char *a = fi->hfinfo->abbrev;
        if (strncmp(a, "mms.", 4) != 0) continue;
        const char *s = a + 4; /* tail after "mms." */

        if      (!strcmp(s, "initiate_RequestPDU_element"))   flags->has_initiate_req   = TRUE;
        else if (!strcmp(s, "initiate_ResponsePDU_element"))  flags->has_initiate_resp  = TRUE;
        else if (!strcmp(s, "conclude_RequestPDU_element"))   flags->has_conclude_req   = TRUE;
        else if (!strcmp(s, "conclude_ResponsePDU_element"))  flags->has_conclude_resp  = TRUE;
        else if (!strcmp(s, "rejectPDU_element"))             flags->has_reject         = TRUE;
        else if (!strcmp(s, "informationReport_element"))     flags->has_info_report    = TRUE;
        else if (!strcmp(s, "confirmed_RequestPDU_element"))  flags->has_confirmed_req  = TRUE;
        else if (!strcmp(s, "confirmed_ResponsePDU_element")) flags->has_confirmed_resp = TRUE;
        else if (!strcmp(s, "confirmed_ErrorPDU_element"))    flags->has_confirmed_err  = TRUE;
        else if (!strcmp(s, "read_element"))                  flags->has_read           = TRUE;
        else if (!strcmp(s, "write_element"))                 flags->has_write          = TRUE;
        else if (!strcmp(s, "getNameList_element"))           flags->has_get_namelist   = TRUE;
        else if (!strcmp(s, "getVariableAccessAttributes_element")) flags->has_get_var_attr = TRUE;
        else if (!strcmp(s, "defineNamedVariableList_element"))     flags->has_define_nvl   = TRUE;
        else if (!strcmp(s, "deleteNamedVariableList_element"))     flags->has_delete_nvl   = TRUE;
        /* Data / Report accounting. These are cumulative per-packet
         * counters; caller decides whether to surface them (typically
         * only for InformationReport / Read-Response PDUs). */
        else if (!strcmp(s, "AccessResult"))        flags->access_result_count++;
        /* mms.failure (FT_INT32) fires once per failed AccessResult.
         * The MMS dissector does not emit a corresponding
         * mms.success_element, so we derive the success count as
         * total AccessResult items minus failure count. */
        else if (!strcmp(s, "failure"))             flags->failure_count++;
        /* MMS emits the structure-count item under abbrev "mms.structure"
         * in 4.2.x and 4.6 alike (verified empirically via -T fields).
         * The duplicate hf "mms.structure_element" exists in the asn2wrs
         * registration table but is never actually emitted, at least in
         * the 4.2.2 / 4.2.3 dissector. Match both names for safety. */
        else if (!strcmp(s, "structure") || !strcmp(s, "structure_element"))
            flags->structure_count++;
        else if (!strcmp(s, "floating_point"))      flags->floating_point_count++;
        else if (!strcmp(s, "data_bit-string"))     flags->bit_string_count++;
        else if (!strcmp(s, "data.binary-time"))    flags->binary_time_count++;
        else if (!strcmp(s, "data.visible-string")) flags->visible_string_count++;
        else if (!strcmp(s, "data.octet-string"))   flags->octet_string_count++;
        /* Variable-identifier fields: Identifier, itemId, vmd_specific,
         * newIdentifier. These carry the actual variable / object name
         * we want to classify and surface as iccp.object.name. */
        else if (!strcmp(s, "Identifier")
              || !strcmp(s, "itemId")
              /* 4.6 abbrev for the same itemId field. asn2wrs renamed the
               * generated hfid path from "mms.itemId" to
               * "mms.objectName_domain_specific_itemId" -- without this
               * branch, walk_tree finds no name, scan.matched stays NULL,
               * and the per-Transfer-Set stats axis collapses to a single
               * "(unnamed)" bucket on every report. */
              || !strcmp(s, "objectName_domain_specific_itemId")
              || !strcmp(s, "vmd_specific")
              || !strcmp(s, "aa_specific")
              || !strcmp(s, "newIdentifier")) {
            if (fi->value) {
                const char *sv = fvalue_get_string(fi->value);
                iccp_consider_name(scan, sv);
                /* mms.vmd_specific marks a VCC-scope name. */
                if (!strcmp(s, "vmd_specific") && scan->scope == ICCP_SCOPE_NONE)
                    scan->scope = ICCP_SCOPE_VCC;
            }
        }
        /* Domain-marker fields: domainId carries the Bilateral Table id;
         * domainSpecific is the SEQUENCE wrapper that confirms scope.
         * These do NOT feed iccp_consider_name -- the domain is not the
         * "name we care about" for object classification or stats
         * bucketing; that's the variable identifier inside the domain. */
        else if (!strcmp(s, "domainId")) {
            if (fi->value) {
                scan->scope     = ICCP_SCOPE_BILATERAL;
                scan->domain_id = fvalue_get_string(fi->value);
            }
        }
        else if (!strcmp(s, "domainSpecific")) {
            if (scan->scope == ICCP_SCOPE_NONE)
                scan->scope = ICCP_SCOPE_BILATERAL;
        }
    }
    g_ptr_array_free(all, TRUE);
}

/* -------------------------------------------------------------------------
 * Post-dissector
 * ---------------------------------------------------------------------- */

static iccp_op_t
classify_operation(const iccp_pdu_flags_t *f)
{
    if (f->has_initiate_req)   return ICCP_OP_ASSOC_REQ;
    if (f->has_initiate_resp)  return ICCP_OP_ASSOC_RESP;
    if (f->has_conclude_req)   return ICCP_OP_CONCLUDE_REQ;
    if (f->has_conclude_resp)  return ICCP_OP_CONCLUDE_RESP;
    if (f->has_reject)         return ICCP_OP_REJECT;
    if (f->has_info_report)    return ICCP_OP_INFORMATION_REPORT;

    if (f->has_confirmed_req) {
        if (f->has_read)           return ICCP_OP_READ_REQ;
        if (f->has_write)          return ICCP_OP_WRITE_REQ;
        if (f->has_get_namelist)   return ICCP_OP_GET_NAMELIST_REQ;
        if (f->has_get_var_attr)   return ICCP_OP_GET_VAR_ATTR_REQ;
        if (f->has_define_nvl)     return ICCP_OP_DEFINE_NVL_REQ;
        if (f->has_delete_nvl)     return ICCP_OP_DELETE_NVL_REQ;
    } else if (f->has_confirmed_resp) {
        if (f->has_read)           return ICCP_OP_READ_RESP;
        if (f->has_write)          return ICCP_OP_WRITE_RESP;
        if (f->has_get_namelist)   return ICCP_OP_GET_NAMELIST_RESP;
        if (f->has_get_var_attr)   return ICCP_OP_GET_VAR_ATTR_RESP;
        if (f->has_define_nvl)     return ICCP_OP_DEFINE_NVL_RESP;
        if (f->has_delete_nvl)     return ICCP_OP_DELETE_NVL_RESP;
    }

    if (f->has_confirmed_err)  return ICCP_OP_CONFIRMED_ERROR;

    return ICCP_OP_NONE;
}

/* Per-point timestamp captured from a TASE.2 RealQTimeTag /
 * RealQTimeTagExtended IndicationPoint shape. ts is the absolute UTC
 * time decoded from BinaryTime6 (length 6) or BinaryTime8 (length 8).
 * ms_extended carries the raw 16-bit fractional-ms field present on
 * length-8 form (per IEC 60870-6 Annex C, "fractional ms in units of
 * 1/2^16 ms"). length 4 BinaryTimes only carry ms-of-day with no
 * date; we store them as ts.secs in 0..86399 with a TRUE has_time_only
 * flag so consumers know not to treat secs as a unix timestamp. */
typedef struct {
    nstime_t ts;
    guint16  ms_extended;
    gboolean has_ms_extended;   /* TRUE iff BinaryTime8 (8 bytes) */
    gboolean has_time_only;     /* TRUE iff BinaryTime4 (no date) */
} iccp_point_time_t;

/* Forward decls -- these helpers live further down (near the BER
 * byte-walker) but maybe_synthesise_point above uses them. */
static gboolean iccp_decode_binary_time(tvbuff_t *tvb, int offset, int length,
                                        iccp_point_time_t *out);
static void     iccp_format_point_time(char *buf, size_t buflen,
                                        const iccp_point_time_t *pt);

/* Per-walk context so we can number points and emit aggregate stats. */
typedef struct {
    guint32  point_index;        /* incremented as we synthesise iccp.point rows */
    /* Per-PDU point statistics, harvested by maybe_synthesise_point()
     * for the post-dissector to forward to the tap. */
    guint32  points_valid;
    guint32  points_held;
    guint32  points_suspect;
    guint32  points_notvalid;
    /* Per-PDU CurrentSource histogram (TASE.2 IEC 60870-6-802 §8.2.1).
     * Bits 3-2 of the quality byte. Maps point provenance:
     * TELEMETERED = real telemetry, CALCULATED = derived,
     * ENTERED = manually keyed, ESTIMATED = system fill-in. */
    guint32  points_telemetered;
    guint32  points_calculated;
    guint32  points_entered;
    guint32  points_estimated;
    gfloat   v_min;
    gfloat   v_max;
    gfloat   v_sum;
    gboolean has_value;
    /* Optional per-point capture for STAT_DT_FLOAT stats axes. Set up
     * by the caller using pinfo->pool; maybe_synthesise_point appends
     * one (value, validity_class) pair per recognised IndicationPoint.
     * NULL means "skip per-point capture" (the stats listener will
     * still get the aggregate min/max/sum on the tap). */
    wmem_array_t *point_values;       /* gfloat per element */
    wmem_array_t *point_validities;   /* guint8 per element, 0..3 */
    /* Slot of each point in the parent listOfAccessResult. Filled by the
     * BER walker, which is the only path that knows the wire-position.
     * The proto-tree walk path (attach_decoded_values) doesn't populate
     * this array -- on a Wireshark version with the MMS bug it has at
     * most one entry to fill anyway. Length matches point_values when
     * the BER walker provided the points; may be 0 when only the tree
     * walk fed point_values. */
    wmem_array_t *point_slots;        /* guint32 per element */
    /* Optional per-point timestamp capture for TASE.2 RealQTimeTag /
     * RealQTimeTagExtended IndicationPoints. Both walkers append one
     * iccp_point_time_t per binary-time leaf they encounter inside a
     * point structure. NULL means "skip timestamp capture". */
    wmem_array_t *point_timestamps;   /* iccp_point_time_t per element */
    /* Frame's wire timestamp (pinfo->abs_ts) -- used to derive the
     * iccp.point.timestamp.age relative-time field. Populated by
     * dissect_iccp / iccp_force_tree_packet alongside the per-point
     * arrays. Zero on contexts that don't have a frame (regression
     * fixtures), in which case age computation is skipped. */
    nstime_t frame_abs_ts;
    /* When TRUE, the walker collects counters and per-point arrays but
     * does NOT mutate the proto tree (no [Decoded float], no [Quality
     * decoded], no Point #N synthesis rows). Used by the always-on
     * "frame" tap listener which re-runs the analysis on edt->tree
     * AFTER the dissector pass added those items: a second pass that
     * re-added them would duplicate every Point #N row in the GUI
     * detail pane. */
    gboolean read_only;
    /* Tree the BER walker emits hidden iccp.point.value /
     * iccp.point.quality items into, so display filters that reference
     * those fields match every frame -- even in non-visible tree mode
     * (Wireshark GUI's filter scan, tshark -2 default summary) where
     * MMS items are faked out and attach_decoded_values' tree walk
     * finds nothing to synthesise from. NULL means "don't emit hidden
     * items"; the BER walker still updates counters and arrays. */
    proto_tree *hidden_tree;
    /* Data-set reference extracted from variableAccessSpecification
     * variableListName [1] of an unconfirmed informationReport (or the
     * write/read variants). Domain + item identify the DSD that bound
     * slots to variable names; iccp_dsd_lookup keys off these.
     * Strings are pinfo->pool-scoped (live for the dissection only). */
    const char *ds_domain;
    const char *ds_item;
    /* Every slot-level 4-byte MMS INTEGER (Data CHOICE alt [5] / [6]
     * IMPLICIT, tag 0x85 / 0x86) seen at the outer listOfAccessResult
     * level (depth == 0). The post-walk consumer iterates this list,
     * looks each candidate's slot up against the DSD, and promotes the
     * one whose name matches "Transfer_Set_Time_Stamp" (and whose
     * value falls in a Y2000..Y2100 Unix-seconds window) to the
     * iccp.transfer_set.timestamp field. Capturing every candidate --
     * not just the first -- guards against DSDs where a non-timestamp
     * INTEGER appears at a lower slot than the actual timestamp
     * (Codex review caught this). Only the BER walker populates this;
     * the proto-tree walker doesn't track slot-typed integers.
     * Element type is iccp_ts_candidate_t (forward-declared below). */
    wmem_array_t *ts_candidates;
} iccp_walk_ctx_t;

typedef struct {
    guint32 slot;       /* listOfAccessResult slot index (0-based) */
    guint32 raw;        /* 4-byte BE INTEGER as unsigned */
} iccp_ts_candidate_t;

static void attach_decoded_values(proto_node *node, gpointer user_data);

/* If `node` is an mms.structure_element with two primitive children
 * matching the canonical TASE.2 IndicationPoint shape (floating_point
 * + bit-string), synthesise a single iccp.point row that puts the
 * decoded value and quality on one line. */
static void
maybe_synthesise_point(proto_node *node, iccp_walk_ctx_t *ctx)
{
    field_info *fi = PNODE_FINFO(node);
    if (!fi || !fi->hfinfo || !fi->hfinfo->abbrev) return;
    /* The innermost SEQUENCE wrapper for an MMS Data.structure carries
     * different abbrevs across Wireshark versions:
     *   4.2 uses "mms.structure_element" (FT_NONE element wrapper)
     *   4.6 uses "mms.structure"         (FT_UINT32 CHOICE selector)
     * We accept either. Only one will exist in any given runtime so
     * there's no double-emission risk. */
    const char *a = fi->hfinfo->abbrev;
    if (strcmp(a, "mms.structure_element") != 0
     && strcmp(a, "mms.structure")         != 0) {
        return;
    }

    /* Walk the entire subtree under `node`, collecting any
     * floating_point and data_bit-string leaves. We don't insist on
     * a specific intermediate path because the MMS dissector wraps
     * primitives in either mms.Data (CHOICE selector) or
     * mms.data_element (FT_NONE element wrapper) depending on the
     * dissector version. As long as the structure has exactly one
     * float and one bit-string, treat it as an IndicationPoint. */
    proto_node *fp_node     = NULL;
    proto_node *bs_nodes[3] = { NULL, NULL, NULL };  /* up to 3 for StateSupplemental */
    proto_node *int_node    = NULL;
    proto_node *bt_node     = NULL;
    int floats = 0, bitstrings = 0, integers = 0, binary_times = 0;
    /* Bounded depth-first walk over node's descendants. */
    typedef struct stk_s { proto_node *p; struct stk_s *next; } stk_t;
    stk_t *stack = NULL;
    for (proto_node *c = node->first_child; c; c = c->next) {
        stk_t *s = (stk_t *)g_alloca(sizeof(stk_t));
        s->p = c; s->next = stack; stack = s;
    }
    while (stack) {
        proto_node *cur = stack->p;
        stack = stack->next;
        field_info *cfi = PNODE_FINFO(cur);
        if (cfi && cfi->hfinfo && cfi->hfinfo->abbrev) {
            const char *abbr = cfi->hfinfo->abbrev;
            if (strcmp(abbr, "mms.floating_point") == 0) {
                if (!fp_node) fp_node = cur;
                floats++;
            } else if (strcmp(abbr, "mms.data_bit-string") == 0) {
                if (bitstrings < 3) bs_nodes[bitstrings] = cur;
                bitstrings++;
            } else if (strcmp(abbr, "mms.integer") == 0
                    || strcmp(abbr, "mms.unsigned") == 0) {
                if (!int_node) int_node = cur;
                integers++;
            } else if (strcmp(abbr, "mms.data.binary-time") == 0) {
                if (binary_times == 0) bt_node = cur;
                binary_times++;
            }
        }
        for (proto_node *cc = cur->first_child; cc; cc = cc->next) {
            stk_t *s = (stk_t *)g_alloca(sizeof(stk_t));
            s->p = cc; s->next = stack; stack = s;
        }
    }
    /* Determine the IndicationPoint shape per IEC 60870-6-802:
     *   Real / RealQ / RealQTimeTag : 1 float + 1 bit-string [+ 1 binary-time]
     *   Discrete / DiscreteQ        : 1 integer + 1 bit-string
     *   State / StateQ              : 0 floats + 0 integers + 2 bit-strings
     *                                 (first = DoubleState, second = quality)
     *   StateSupplemental(Q)        : 0 floats + 0 integers + 3 bit-strings
     *                                 (first = state, second = supp flags,
     *                                  third = quality) */
    enum {
        PSHAPE_NONE,
        PSHAPE_REAL,        /* float + quality, optional binary-time */
        PSHAPE_DISCRETE,    /* integer + quality */
        PSHAPE_STATE,       /* state-2bit + quality */
        PSHAPE_STATE_SUP,   /* state-2bit + supp flags + quality */
    } pshape = PSHAPE_NONE;

    /* All four shapes may also carry an optional BinaryTime
     * (RealQTimeTag / StateQTimeTag / DiscreteQTimeTag etc.). */
    if (binary_times > 1) return;
    if (floats == 1 && integers == 0 && bitstrings == 1) {
        pshape = PSHAPE_REAL;
    } else if (floats == 0 && integers == 1 && bitstrings == 1) {
        pshape = PSHAPE_DISCRETE;
    } else if (floats == 0 && integers == 0 && bitstrings == 2) {
        pshape = PSHAPE_STATE;
    } else if (floats == 0 && integers == 0 && bitstrings == 3) {
        pshape = PSHAPE_STATE_SUP;
    } else {
        return;  /* unknown / ambiguous shape -- don't synthesise */
    }

    /* Quality is the LAST bit-string in the structure regardless of
     * shape. For Real/Discrete that's bs_nodes[0]; for State that's
     * bs_nodes[1]; for StateSupplemental that's bs_nodes[2]. */
    proto_node *quality_node = NULL;
    proto_node *value_node   = NULL;
    proto_node *supp_node    = NULL;
    switch (pshape) {
        case PSHAPE_REAL:
            value_node = fp_node; quality_node = bs_nodes[0]; break;
        case PSHAPE_DISCRETE:
            value_node = int_node; quality_node = bs_nodes[0]; break;
        case PSHAPE_STATE:
            value_node = bs_nodes[0]; quality_node = bs_nodes[1]; break;
        case PSHAPE_STATE_SUP:
            value_node = bs_nodes[0]; supp_node = bs_nodes[1];
            quality_node = bs_nodes[2]; break;
        default: return;
    }

    field_info *qfi = PNODE_FINFO(quality_node);
    if (!qfi || qfi->length < 2 || !qfi->ds_tvb) return;
    /* Quality bit-string content layout: byte 0 = unused-bits count,
     * byte 1 = the 8 quality flag bits. We always read byte 1. */
    guint8 q = tvb_get_guint8(qfi->ds_tvb, qfi->start + 1);

    /* Decode the value -- type-specific. */
    char vbuf[80] = {0};                /* one-line display string */
    gfloat  v_real     = 0.0f;          /* real point value */
    gint32  v_discrete = 0;             /* discrete point integer */
    guint8  v_state    = 0;             /* DoubleState 0..3 */
    guint8  v_supp     = 0;             /* StateSupplemental flags byte */
    static const char *state_names[4] = {
        "INTERMEDIATE", "OFF", "ON", "INVALID"
    };

    if (pshape == PSHAPE_REAL) {
        field_info *fp_fi = PNODE_FINFO(value_node);
        if (!fp_fi || fp_fi->length < 5 || !fp_fi->ds_tvb) return;
        if (tvb_get_guint8(fp_fi->ds_tvb, fp_fi->start) != 8) return;
        v_real = tvb_get_ntohieee_float(fp_fi->ds_tvb, fp_fi->start + 1);
        g_snprintf(vbuf, sizeof vbuf, "%.6g", (double)v_real);
    } else if (pshape == PSHAPE_DISCRETE) {
        field_info *ifi = PNODE_FINFO(value_node);
        if (!ifi || !ifi->value) return;
        v_discrete = fvalue_get_sinteger(ifi->value);
        g_snprintf(vbuf, sizeof vbuf, "%d", v_discrete);
    } else { /* STATE or STATE_SUP */
        field_info *sfi = PNODE_FINFO(value_node);
        if (!sfi || sfi->length < 2 || !sfi->ds_tvb) return;
        /* DoubleState: 2 bits in byte 1, high bits = state value. */
        guint8 sbits = tvb_get_guint8(sfi->ds_tvb, sfi->start + 1);
        v_state = (sbits >> 6) & 0x03;
        if (pshape == PSHAPE_STATE_SUP && supp_node) {
            field_info *spfi = PNODE_FINFO(supp_node);
            if (spfi && spfi->length >= 2 && spfi->ds_tvb) {
                v_supp = tvb_get_guint8(spfi->ds_tvb, spfi->start + 1);
            }
            g_snprintf(vbuf, sizeof vbuf, "%s+sup=0x%02x",
                       state_names[v_state], v_supp);
        } else {
            g_snprintf(vbuf, sizeof vbuf, "%s", state_names[v_state]);
        }
    }

    /* Optional BinaryTime decode -- can attach to any of the four
     * shapes (RealQTimeTag, StateQTimeTag, DiscreteQTimeTag, etc.). */
    iccp_point_time_t pt = { 0 };
    gboolean          have_pt = FALSE;
    char              tsbuf[40] = {0};
    if (bt_node) {
        field_info *bt_fi = PNODE_FINFO(bt_node);
        if (bt_fi && bt_fi->ds_tvb) {
            have_pt = iccp_decode_binary_time(bt_fi->ds_tvb, bt_fi->start,
                                              bt_fi->length, &pt);
            if (have_pt) iccp_format_point_time(tsbuf, sizeof tsbuf, &pt);
        }
    }

    char qbuf[64];
    iccp_quality_summary(qbuf, sizeof qbuf, q);

    /* Type tag in the synthesised line so analysts can see at a glance
     * which IndicationPoint shape this row decoded as. */
    const char *type_tag =
        pshape == PSHAPE_REAL      ? ""              :
        pshape == PSHAPE_DISCRETE  ? " (int)"        :
        pshape == PSHAPE_STATE     ? " (state)"      :
        pshape == PSHAPE_STATE_SUP ? " (state-sup)"  :
                                     "";
    char line[256];
    if (have_pt) {
        g_snprintf(line, sizeof line, "Point #%u%s: %s  [%s] @ %s",
                   ctx->point_index, type_tag, vbuf, qbuf, tsbuf);
    } else {
        g_snprintf(line, sizeof line, "Point #%u%s: %s  [%s]",
                   ctx->point_index, type_tag, vbuf, qbuf);
    }
    ctx->point_index++;

    /* Emit synthesised proto items (skipped in read_only mode). */
    if (!ctx->read_only) {
        field_info *val_fi = PNODE_FINFO(value_node);
        if (val_fi && val_fi->ds_tvb) {
            proto_tree *sub = proto_item_add_subtree(node, ett_iccp_point);
            proto_item *pit = proto_tree_add_string(sub, hf_iccp_point_summary,
                                                    val_fi->ds_tvb,
                                                    val_fi->start,
                                                    (qfi->start + qfi->length)
                                                      - val_fi->start,
                                                    line);
            proto_item_set_generated(pit);
            proto_tree *psub = proto_item_add_subtree(pit, ett_iccp_point);

            /* Type-specific value field. */
            if (pshape == PSHAPE_REAL) {
                proto_item *vi = proto_tree_add_double(psub, hf_iccp_point_value,
                                                       val_fi->ds_tvb, val_fi->start,
                                                       val_fi->length, (gdouble)v_real);
                proto_item_set_generated(vi);
            } else if (pshape == PSHAPE_DISCRETE) {
                proto_item *vi = proto_tree_add_int(psub, hf_iccp_point_discrete,
                                                    val_fi->ds_tvb, val_fi->start,
                                                    val_fi->length, v_discrete);
                proto_item_set_generated(vi);
            } else { /* STATE / STATE_SUP */
                proto_item *vi = proto_tree_add_string(psub, hf_iccp_point_state,
                                                       val_fi->ds_tvb, val_fi->start,
                                                       val_fi->length,
                                                       state_names[v_state]);
                proto_item_set_generated(vi);
                if (pshape == PSHAPE_STATE_SUP && supp_node) {
                    field_info *spfi = PNODE_FINFO(supp_node);
                    if (spfi && spfi->ds_tvb) {
                        proto_item *xi = proto_tree_add_uint(psub,
                                                             hf_iccp_point_state_supplemental,
                                                             spfi->ds_tvb, spfi->start,
                                                             spfi->length, v_supp);
                        proto_item_set_generated(xi);
                    }
                }
            }

            proto_item *qi = proto_tree_add_string(psub, hf_iccp_point_quality,
                                                   qfi->ds_tvb, qfi->start,
                                                   qfi->length, qbuf);
            proto_item_set_generated(qi);
            proto_item *ii = proto_tree_add_uint(psub, hf_iccp_point_index,
                                                 val_fi->ds_tvb, val_fi->start, 0,
                                                 ctx->point_index - 1);
            proto_item_set_generated(ii);

            /* BinaryTime children (Real only). */
            if (have_pt && bt_node) {
                field_info *bt_fi = PNODE_FINFO(bt_node);
                if (bt_fi && bt_fi->ds_tvb) {
                    proto_item *ti = proto_tree_add_time(psub, hf_iccp_point_timestamp,
                                                         bt_fi->ds_tvb, bt_fi->start,
                                                         bt_fi->length, &pt.ts);
                    proto_item_set_generated(ti);
                    if (pt.has_ms_extended) {
                        proto_item *xi = proto_tree_add_uint(psub,
                                                             hf_iccp_point_timestamp_ms_extended,
                                                             bt_fi->ds_tvb,
                                                             bt_fi->start + 6, 2,
                                                             pt.ms_extended);
                        proto_item_set_generated(xi);
                    }
                    if (!pt.has_time_only) {
                        nstime_t age;
                        nstime_delta(&age, &ctx->frame_abs_ts, &pt.ts);
                        proto_item *ai = proto_tree_add_time(psub,
                                                             hf_iccp_point_timestamp_age,
                                                             bt_fi->ds_tvb,
                                                             bt_fi->start,
                                                             bt_fi->length, &age);
                        proto_item_set_generated(ai);
                    }
                }
            }
        }
    }

    /* Capture timestamp into the per-point array (zero entry for
     * shapes / packets without a BinaryTime, so indices stay aligned
     * with point_values / point_validities). */
    if (ctx->point_timestamps) {
        wmem_array_append_one(ctx->point_timestamps, pt);
    }

    /* Per-PDU validity / source histograms -- always derived from the
     * quality byte regardless of point shape. */
    guint8 vc = (guint8)((q & ICCP_Q_VALIDITY_MASK) >> 6);
    switch (vc) {
        case 0: ctx->points_valid++;    break;
        case 1: ctx->points_held++;     break;
        case 2: ctx->points_suspect++;  break;
        case 3: ctx->points_notvalid++; break;
    }
    guint8 src = (guint8)((q & ICCP_Q_SOURCE_MASK) >> 2);
    switch (src) {
        case 0: ctx->points_telemetered++; break;
        case 1: ctx->points_calculated++;  break;
        case 2: ctx->points_entered++;     break;
        case 3: ctx->points_estimated++;   break;
    }

    /* Per-point Real value tracking -- min/max/sum/array only make
     * sense for Real shape. State/Discrete contribute to the validity
     * and source histograms but not to the value distribution axes. */
    if (pshape == PSHAPE_REAL) {
        if (!ctx->has_value || v_real < ctx->v_min) ctx->v_min = v_real;
        if (!ctx->has_value || v_real > ctx->v_max) ctx->v_max = v_real;
        ctx->v_sum    += v_real;
        ctx->has_value = TRUE;
        if (ctx->point_values) {
            wmem_array_append_one(ctx->point_values, v_real);
        }
    }
    if (ctx->point_validities) {
        wmem_array_append_one(ctx->point_validities, vc);
    }
}

/* If `node` is an mms.data_bit-string of length 1, treat it as a
 * TASE.2 IndicationPoint quality byte and decode each flag bit as
 * a child item. */
static void
maybe_decode_quality(proto_node *node)
{
    field_info *fi = PNODE_FINFO(node);
    if (!fi || !fi->hfinfo || !fi->hfinfo->abbrev) return;
    if (strcmp(fi->hfinfo->abbrev, "mms.data_bit-string") != 0) return;
    if (fi->length != 1 || !fi->ds_tvb) return;

    guint8 q = tvb_get_guint8(fi->ds_tvb, fi->start);
    char buf[64];
    iccp_quality_summary(buf, sizeof buf, q);

    proto_tree *sub = proto_item_add_subtree(node, ett_iccp_quality);
    proto_item *summary_it = proto_tree_add_string(sub, hf_iccp_quality_summary,
                                                   fi->ds_tvb, fi->start,
                                                   fi->length, buf);
    proto_item_set_generated(summary_it);
    /* Hidden parent uint8 carries the bitmask; children render the
     * individual fields via the registered masks. */
    proto_item *q_item = proto_tree_add_uint(sub, hf_iccp_quality,
                                             fi->ds_tvb, fi->start, 1, q);
    proto_item_set_generated(q_item);
    proto_tree *qsub = proto_item_add_subtree(q_item, ett_iccp_quality);
    proto_tree_add_item(qsub, hf_iccp_quality_validity,
                        fi->ds_tvb, fi->start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(qsub, hf_iccp_quality_normal,
                        fi->ds_tvb, fi->start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(qsub, hf_iccp_quality_ts_invalid,
                        fi->ds_tvb, fi->start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(qsub, hf_iccp_quality_source,
                        fi->ds_tvb, fi->start, 1, ENC_BIG_ENDIAN);
}

/* Decode a 5-byte mms.floating_point as a real number and add it
 * as a generated child of the leaf. */
static void
maybe_decode_float(proto_node *node)
{
    field_info *fi = PNODE_FINFO(node);
    if (!fi || !fi->hfinfo || !fi->hfinfo->abbrev) return;
    if (strcmp(fi->hfinfo->abbrev, "mms.floating_point") != 0) return;
    if (fi->length < 5 || !fi->ds_tvb) return;
    if (tvb_get_guint8(fi->ds_tvb, fi->start) != 8) return;

    gfloat val = tvb_get_ntohieee_float(fi->ds_tvb, fi->start + 1);
    proto_tree *sub = proto_item_add_subtree(node, ett_iccp_value);
    proto_item *it = proto_tree_add_double(sub, hf_iccp_value_real,
                                           fi->ds_tvb, fi->start,
                                           fi->length, (gdouble)val);
    proto_item_set_generated(it);
}

/* Recursive tree-walker that runs three passes per node:
 *   1. decode mms.floating_point bytes as a real number
 *   2. decode mms.data_bit-string of length 1 as quality flags
 *   3. detect (floating_point, bit-string) pairs inside a structure
 *      and synthesise a single-line "Point #N: V [quality]" row
 * then descends into children. */
static void
attach_decoded_values(proto_node *node, gpointer user_data)
{
    if (!node) return;
    iccp_walk_ctx_t *ctx = (iccp_walk_ctx_t *)user_data;

    /* Tree mutators (decoded float, quality bit-string decode, point
     * synthesis subtree) only fire on the dissector pass. In read_only
     * mode the listener re-runs the walk solely to populate per-point
     * counters and arrays for tap delivery; the dissector already
     * emitted the GUI items. */
    if (!ctx || !ctx->read_only) {
        maybe_decode_float(node);
        maybe_decode_quality(node);
    }
    if (ctx) maybe_synthesise_point(node, ctx);

    proto_tree_children_foreach(node, attach_decoded_values, ctx);
}

/* -------------------------------------------------------------------------
 * BER recovery walker
 *
 * Wireshark's MMS dissector hits a recursion-depth assertion in
 * mms.c:2103 once a SEQUENCE OF Data has more than ~2 items. When that
 * fires, MMS aborts mid-list and the per-item fields (mms.floating_point,
 * mms.data_bit-string, mms.AccessResult, ...) are NOT placed in the
 * proto tree past the bug threshold. walk_tree() above sees only the
 * first 1-2 items and undercounts everything by an order of magnitude.
 *
 * The recovery walker decodes the MMS PDU's listOfAccessResult /
 * listOfData directly from the BER bytes and updates the same
 * iccp_pdu_flags_t counters + the iccp_walk_ctx_t point arrays. It runs
 * after walk_tree() and *raises* the counts so the recovered values win
 * whenever MMS gave up early.
 *
 * Handles the three MMS PDU shapes that carry SEQUENCE OF Data:
 *   - InformationReport       A3 > A0 > [varAccessSpec] > A0 (listOfAccessResult)
 *   - Confirmed-Request.write A0 > [02 invokeID] > A5 > [varAccessSpec] > A0 (listOfData)
 *   - Confirmed-Response.read A1 > [02 invokeID] > A4 > [varAccessSpec OPT] > A1 (listOfAccessResult)
 *
 * No proto-tree side effects -- this is a counting / value-extraction
 * pass only. attach_decoded_values() still adds Point #N rows for items
 * the MMS dissector DID place in the tree; recovered items past the bug
 * threshold contribute to counts and stats but not to per-row tree
 * visualization (could be added later by emitting hf_iccp_point_value /
 * hf_iccp_point_quality items here too).
 *
 * Best-effort: any malformed BER aborts the walk gracefully without
 * recording garbage. 16-level depth limit on nested structure/array.
 * ---------------------------------------------------------------------- */

static gboolean
iccp_ber_read_tl(const guint8 **p, const guint8 *end,
                 guint8 *tag_out, guint32 *len_out)
{
    if (*p >= end) return FALSE;
    guint8 tag = *(*p)++;
    if (*p >= end) return FALSE;
    guint8 b = *(*p)++;
    guint32 len;
    if (b < 0x80) {
        len = b;
    } else {
        guint8 n = b & 0x7f;
        if (n == 0 || n > 4 || (gsize)(end - *p) < n) return FALSE;
        len = 0;
        for (guint8 i = 0; i < n; i++) len = (len << 8) | *(*p)++;
    }
    if ((gsize)(end - *p) < len) return FALSE;
    *tag_out = tag;
    *len_out = len;
    return TRUE;
}

/* TASE.2 quality byte high two bits encode validity:
 *   00 = VALID, 01 = HELD, 10 = SUSPECT, 11 = NOT_VALID.
 * Returned class index matches what maybe_synthesise_point uses
 * ((q & ICCP_Q_VALIDITY_MASK) >> 6) so the stats / tap-info /
 * point_validities array indices line up with the existing axis. */
static guint8
iccp_quality_validity_class(guint8 q)
{
    return (guint8)((q & 0xC0) >> 6);
}

/* MMS BinaryTime epoch: 1984-01-01 00:00:00 UTC.
 * Constant used by iccp_decode_binary_time. */
#define ICCP_BINARY_TIME_EPOCH ((time_t)441763200)

/* Decode an MMS BinaryTime / TASE.2 IndicationPoint timestamp.
 *
 *   length 4: ms-of-day uint32 BE only (no date) -- "TimeOfDay" form
 *   length 6: ms-of-day uint32 BE + days-since-1984 uint16 BE
 *             ("BinaryTime6" / RealQTimeTag)
 *   length 8: BinaryTime6 + 2-byte fractional-ms extension uint16 BE
 *             ("BinaryTime8" / RealQTimeTagExtended)
 *
 * Returns FALSE if the length isn't one of those three or the bytes
 * are out-of-range. On success out->ts holds the decoded UTC time
 * (or, for length 4, secs in 0..86399 with has_time_only=TRUE). The
 * 16-bit fractional ms is in out->ms_extended for length 8; we do NOT
 * fold it into ts.nsecs because vendor interpretations of the fraction
 * vary (1/65536 ms vs straight microseconds vs proprietary). Callers
 * that need sub-millisecond precision can compute it from ms_extended. */
static gboolean
iccp_decode_binary_time(tvbuff_t *tvb, int offset, int length,
                        iccp_point_time_t *out)
{
    if (!out || !tvb) return FALSE;
    if (length != 4 && length != 6 && length != 8) return FALSE;

    nstime_set_zero(&out->ts);
    out->ms_extended     = 0;
    out->has_ms_extended = FALSE;
    out->has_time_only   = FALSE;

    guint32 ms_of_day = tvb_get_ntohl(tvb, offset);
    if (ms_of_day > 86400000U) return FALSE;

    out->ts.secs  = (time_t)(ms_of_day / 1000);
    out->ts.nsecs = (int)((ms_of_day % 1000) * 1000000);

    if (length == 4) {
        out->has_time_only = TRUE;
        return TRUE;
    }

    guint16 days = tvb_get_ntohs(tvb, offset + 4);
    out->ts.secs += ICCP_BINARY_TIME_EPOCH + (time_t)days * (time_t)86400;

    if (length == 8) {
        out->ms_extended     = tvb_get_ntohs(tvb, offset + 6);
        out->has_ms_extended = TRUE;
    }
    return TRUE;
}

/* Format a decoded IndicationPoint timestamp into a short
 * "YYYY-MM-DD HH:MM:SS.mmm" (or ".mmm+ext" when extended) string.
 * Buffer should be at least 40 bytes. For has_time_only entries
 * (BinaryTime4) the date prefix is replaced with "(time-of-day) ". */
static void
iccp_format_point_time(char *buf, size_t buflen, const iccp_point_time_t *pt)
{
    if (!buf || buflen == 0 || !pt) {
        if (buf && buflen) buf[0] = '\0';
        return;
    }
    if (pt->has_time_only) {
        guint32 ms = (guint32)(pt->ts.secs * 1000) + (guint32)(pt->ts.nsecs / 1000000);
        guint32 h  = (ms / 3600000U) % 24;
        guint32 m  = (ms / 60000U) % 60;
        guint32 s  = (ms / 1000U) % 60;
        guint32 mr = ms % 1000U;
        g_snprintf(buf, buflen, "(time-of-day) %02u:%02u:%02u.%03u", h, m, s, mr);
        return;
    }
    /* gmtime is portable enough for the 1984..2099 range BinaryTime6 covers. */
    time_t t = pt->ts.secs;
    struct tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    int ms = pt->ts.nsecs / 1000000;
    if (pt->has_ms_extended) {
        g_snprintf(buf, buflen,
                   "%04d-%02d-%02d %02d:%02d:%02d.%03d+%u",
                   tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                   tm.tm_hour, tm.tm_min, tm.tm_sec, ms,
                   (unsigned)pt->ms_extended);
    } else {
        g_snprintf(buf, buflen,
                   "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                   tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                   tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
    }
}

static void
iccp_ber_walk_one_data(tvbuff_t *tvb, const guint8 *base, guint8 tag,
                       const guint8 *content, guint32 len,
                       iccp_pdu_flags_t *flags, iccp_walk_ctx_t *walk_ctx,
                       int depth, guint32 slot)
{
    if (depth > 16) return;
    switch (tag) {
        case 0x83: /* boolean [3] */
            break;
        case 0x84: /* bit-string [4] */
            flags->bit_string_count++;
            if (len >= 2 && walk_ctx) {
                /* content[0] is the unused-bits count; the quality byte is
                 * the next byte. Append the validity class, matching the
                 * mapping the proto-tree-driven path uses. */
                guint8 q  = content[1];
                guint8 vc = iccp_quality_validity_class(q);
                if (walk_ctx->point_validities) {
                    wmem_array_append_one(walk_ctx->point_validities, vc);
                }
                /* Validity histogram (bits 7-6 of quality byte) -- the
                 * proto-tree walker increments these in maybe_synthesise_point;
                 * the BER walker has to do the same so the count-axis
                 * stats fire when MMS aborted before the tree walker
                 * could see the points. */
                switch (vc) {
                    case 0: walk_ctx->points_valid++;    break;
                    case 1: walk_ctx->points_held++;     break;
                    case 2: walk_ctx->points_suspect++;  break;
                    case 3: walk_ctx->points_notvalid++; break;
                }
                /* CurrentSource histogram (bits 3-2 of quality byte) --
                 * bumped on every recovered point so the per-PDU and
                 * per-Transfer-Set stats axes show provenance. */
                switch ((q & 0x0C) >> 2) {
                    case 0: walk_ctx->points_telemetered++; break;
                    case 1: walk_ctx->points_calculated++;  break;
                    case 2: walk_ctx->points_entered++;     break;
                    case 3: walk_ctx->points_estimated++;   break;
                }
                /* Hidden filter-target items so iccp.quality.* and
                 * iccp.quality match in the GUI's filter scan even when
                 * the tree is in non-visible mode and MMS items are
                 * faked away. proto_tree_add_*() honours HF_REF_TYPE_DIRECT
                 * to bypass the fake check, and any filter that mentions
                 * the field marks it direct-ref. */
                if (walk_ctx->hidden_tree && tvb && base) {
                    int offset = (int)(content - base);
                    proto_item *qi = proto_tree_add_uint(walk_ctx->hidden_tree,
                                                         hf_iccp_quality,
                                                         tvb, offset + 1, 1, q);
                    proto_item_set_hidden(qi);
                    proto_item_set_generated(qi);
                    proto_item *vi = proto_tree_add_uint(walk_ctx->hidden_tree,
                                                         hf_iccp_quality_validity,
                                                         tvb, offset + 1, 1, q);
                    proto_item_set_hidden(vi);
                    proto_item_set_generated(vi);
                }
            }
            break;
        case 0x85: /* integer [5] */
        case 0x86: /* unsigned [6] */
            /* Capture every slot-level 4-byte INTEGER as a candidate
             * Transfer_Set_Time_Stamp. Depth == 0 means we are at the
             * outer listOfAccessResult level (nested structures recurse
             * with depth+1) so this won't pick up INTEGER values inside
             * DiscreteQTimeTag-style per-point structures. The
             * post-walk consumer cross-references each candidate's
             * slot against the DSD-resolved variable name and only
             * promotes one whose name matches "Transfer_Set_Time_Stamp"
             * to an absolute time. Multiple candidates are kept because
             * a DSD may legitimately place a non-timestamp INTEGER at
             * a lower slot than the actual timestamp. */
            if (depth == 0 && len == 4 && walk_ctx && walk_ctx->ts_candidates) {
                iccp_ts_candidate_t c;
                c.slot = slot;
                c.raw  =   ((guint32)content[0] << 24)
                         | ((guint32)content[1] << 16)
                         | ((guint32)content[2] <<  8)
                         |  (guint32)content[3];
                wmem_array_append_one(walk_ctx->ts_candidates, c);
            }
            break;
        case 0x87: /* floating-point [7] */
            flags->floating_point_count++;
            if (len >= 5 && walk_ctx) {
                /* TASE.2 floating-point: 1-byte exponent indicator at
                 * content[0] (8 = IEEE-754 single, 11 = double), then
                 * 4 bytes IEEE-754 BE for single. We only handle single
                 * here; doubles are rare in TASE.2 transfer sets. */
                guint32 raw = ((guint32)content[1] << 24)
                            | ((guint32)content[2] << 16)
                            | ((guint32)content[3] <<  8)
                            |  (guint32)content[4];
                gfloat f;
                memcpy(&f, &raw, 4);
                if (walk_ctx->point_values) {
                    wmem_array_append_one(walk_ctx->point_values, f);
                }
                if (walk_ctx->point_slots) {
                    wmem_array_append_one(walk_ctx->point_slots, slot);
                }
                /* Hidden filter-target item. See bit-string case above
                 * for the rationale; this is what makes
                 * `iccp.point.value > 0` and `AVG(iccp.point.value)` work
                 * in the GUI. */
                if (walk_ctx->hidden_tree && tvb && base) {
                    int offset = (int)(content - base);
                    proto_item *vi = proto_tree_add_double(walk_ctx->hidden_tree,
                                                           hf_iccp_point_value,
                                                           tvb, offset + 1, 4,
                                                           (gdouble)f);
                    proto_item_set_hidden(vi);
                    proto_item_set_generated(vi);
                    proto_item *ri = proto_tree_add_double(walk_ctx->hidden_tree,
                                                           hf_iccp_value_real,
                                                           tvb, offset + 1, 4,
                                                           (gdouble)f);
                    proto_item_set_hidden(ri);
                    proto_item_set_generated(ri);
                }
            }
            break;
        case 0x89: /* octet-string [9] */
            flags->octet_string_count++;
            break;
        case 0x8a: /* visible-string [10] */
            flags->visible_string_count++;
            break;
        case 0x88: /* real [8] -- alternate float encoding */
            flags->real_count++;
            break;
        case 0x8b: /* generalized-time [11] */
            flags->generalized_time_count++;
            break;
        case 0x8d: /* bcd [13] */
            flags->bcd_count++;
            break;
        case 0x90: /* mMSString [16] */
            flags->mms_string_count++;
            break;
        case 0x91: /* utc-time [17] -- vendor-specific timestamp encoding */
            flags->utc_time_count++;
            break;
        case 0x8c: /* binary-time [12] -- TASE.2 RealQTimeTag (BinaryTime6 = 6 bytes)
                    * or RealQTimeTagExtended (BinaryTime8 = 8 bytes), or rare
                    * BinaryTime4 (4 bytes, time-of-day only). */
            flags->binary_time_count++;
            if (walk_ctx && walk_ctx->point_timestamps && tvb && base) {
                int offset = (int)(content - base);
                iccp_point_time_t pt;
                if (iccp_decode_binary_time(tvb, offset, (int)len, &pt)) {
                    wmem_array_append_one(walk_ctx->point_timestamps, pt);
                    /* Hidden filter-target items so iccp.point.timestamp /
                     * .ms_extended / .age match in display filter scans
                     * even when MMS is in fake-out tree mode. */
                    if (walk_ctx->hidden_tree) {
                        proto_item *ti = proto_tree_add_time(walk_ctx->hidden_tree,
                                                             hf_iccp_point_timestamp,
                                                             tvb, offset, (int)len,
                                                             &pt.ts);
                        proto_item_set_hidden(ti);
                        proto_item_set_generated(ti);
                        if (pt.has_ms_extended) {
                            proto_item *xi = proto_tree_add_uint(walk_ctx->hidden_tree,
                                                                 hf_iccp_point_timestamp_ms_extended,
                                                                 tvb, offset + 6, 2,
                                                                 pt.ms_extended);
                            proto_item_set_hidden(xi);
                            proto_item_set_generated(xi);
                        }
                        if (!pt.has_time_only
                            && (walk_ctx->frame_abs_ts.secs != 0
                             || walk_ctx->frame_abs_ts.nsecs != 0)) {
                            nstime_t age;
                            nstime_delta(&age, &walk_ctx->frame_abs_ts, &pt.ts);
                            proto_item *ai = proto_tree_add_time(walk_ctx->hidden_tree,
                                                                 hf_iccp_point_timestamp_age,
                                                                 tvb, offset, (int)len,
                                                                 &age);
                            proto_item_set_hidden(ai);
                            proto_item_set_generated(ai);
                        }
                    }
                }
            }
            break;
        case 0xa1: /* array     [1] IMPLICIT SEQUENCE OF Data */
        case 0xa2: /* structure [2] IMPLICIT SEQUENCE OF Data */
            flags->structure_count++;
            {
                const guint8 *p = content, *end = content + len;
                while (p < end) {
                    guint8 t; guint32 l;
                    if (!iccp_ber_read_tl(&p, end, &t, &l)) break;
                    /* Children of a structure inherit the parent's slot
                     * — they're sub-fields of the same listOfAccessResult
                     * item, not separate top-level slots. */
                    iccp_ber_walk_one_data(tvb, base, t, p, l,
                                           flags, walk_ctx, depth + 1, slot);
                    p += l;
                }
            }
            break;
        default:
            /* unknown / unhandled Data alternative — ignore */
            break;
    }
}

/* Walk a SEQUENCE OF AccessResult or SEQUENCE OF Data and update the
 * caller's flags/walk_ctx. is_access_result flips the failure-vs-success
 * dispatch: AccessResult.failure is [0] IMPLICIT (tag 0x80 / 0xa0) while
 * AccessResult.success is bare Data. */
static void
iccp_ber_walk_seq_of(tvbuff_t *tvb, const guint8 *base,
                     const guint8 *content, guint32 len,
                     iccp_pdu_flags_t *flags, iccp_walk_ctx_t *walk_ctx,
                     gboolean is_access_result)
{
    const guint8 *p = content;
    const guint8 *end = content + len;
    guint32 items = 0;
    guint32 failures = 0;
    while (p < end) {
        guint8 t; guint32 l;
        if (!iccp_ber_read_tl(&p, end, &t, &l)) break;
        guint32 slot = items;       /* 0-based listOfAccessResult slot */
        items++;
        if (is_access_result && (t == 0x80 || t == 0xa0)) {
            failures++;
        } else {
            iccp_ber_walk_one_data(tvb, base, t, p, l, flags, walk_ctx, 0, slot);
        }
        p += l;
    }
    if (is_access_result) {
        if (items    > flags->access_result_count) flags->access_result_count = items;
        if (failures > flags->failure_count)       flags->failure_count       = failures;
    }
}

/* Navigate from the MMS PDU root tag to the list-of-Data SEQUENCE OF and
 * walk it. Tolerant: returns silently on any structural mismatch. */
static void
iccp_ber_recover(tvbuff_t *tvb, iccp_pdu_flags_t *flags, iccp_walk_ctx_t *walk_ctx)
{
    if (!tvb || !flags) return;
    gint avail = tvb_captured_length(tvb);
    if (avail < 4) return;
    const guint8 *base = tvb_get_ptr(tvb, 0, avail);
    if (!base) return;
    const guint8 *p = base, *end = base + avail;

    guint8 top_tag; guint32 top_len;
    if (!iccp_ber_read_tl(&p, end, &top_tag, &top_len)) return;
    const guint8 *top_end = p + top_len;

    /* Classify the MMS PDU from its top-level tag. This duplicates what
     * walk_tree derives from MMS proto-tree fields, but runs even when
     * MMS items aren't in the tree -- the case Wireshark's two-pass
     * filter mode and most non-visible dissection paths leave us in.
     * Without this, the surface gate fails on filter-only passes and
     * `iccp` matches zero frames in the GUI even though every clicked
     * frame shows the iccp tree fine. */
    switch (top_tag) {
    case 0xa0: flags->has_confirmed_req  = TRUE; break;
    case 0xa1: flags->has_confirmed_resp = TRUE; break;
    case 0xa2: flags->has_confirmed_err  = TRUE; break;
    case 0xa3: flags->has_info_report    = TRUE; break;
    case 0xa4: flags->has_reject         = TRUE; break;
    case 0xa8: flags->has_initiate_req   = TRUE; break;
    case 0xa9: flags->has_initiate_resp  = TRUE; break;
    case 0xab: flags->has_conclude_req   = TRUE; break;
    case 0xac: flags->has_conclude_resp  = TRUE; break;
    default:   break;
    }

    if (top_tag == 0xa3) {
        /* unconfirmed-PDU: contents are informationReport [0] IMPLICIT (A0) */
        guint8 t; guint32 l;
        if (!iccp_ber_read_tl(&p, top_end, &t, &l)) return;
        if (t != 0xa0) return;
        const guint8 *ir_end = p + l;
        /* variableAccessSpecification CHOICE:
         *   listOfVariable    [0] IMPLICIT SEQ OF VarSpec  (tag 0xa0)
         *   variableListName  [1] EXPLICIT ObjectName      (tag 0xa1)
         * For the [1] form, parse the inner ObjectName -- that's the
         * data-set reference we need to key DSD lookups off. */
        if (!iccp_ber_read_tl(&p, ir_end, &t, &l)) return;
        const guint8 *vas_end = p + l;
        if (t == 0xa1 && walk_ctx) {
            char *dom = NULL, *item = NULL;
            /* Use file scope so the strings survive past iccp_analyse_tree
             * (the walk_ctx fields are read by dissect_iccp later in the
             * same dissection -- packet scope would be safer but is not
             * accessible without pinfo at this layer). Strings are short
             * (<32 chars) and the file scope is freed on file close. */
            if (iccp_ber_read_object_name(&p, vas_end, wmem_file_scope(),
                                          &dom, &item)) {
                walk_ctx->ds_domain = dom;
                walk_ctx->ds_item   = item;
            }
        }
        p = vas_end;
        /* listOfAccessResult [0] IMPLICIT (A0) */
        if (!iccp_ber_read_tl(&p, ir_end, &t, &l)) return;
        if (t != 0xa0) return;
        iccp_ber_walk_seq_of(tvb, base, p, l, flags, walk_ctx, TRUE);
        return;
    }
    if (top_tag == 0xa0) {
        /* confirmed-RequestPDU: invokeID + confirmedServiceRequest CHOICE */
        guint8 t; guint32 l;
        if (!iccp_ber_read_tl(&p, top_end, &t, &l)) return;
        if (t != 0x02) return;
        p += l;
        if (!iccp_ber_read_tl(&p, top_end, &t, &l)) return;
        /* ConfirmedServiceRequest CHOICE inner tags. */
        switch (t) {
        case 0xa1: flags->has_get_namelist = TRUE; break;  /* getNameList    [1] */
        case 0xa4: flags->has_read         = TRUE; break;  /* read           [4] */
        case 0xa5: flags->has_write        = TRUE; break;  /* write          [5] */
        case 0xa6: flags->has_get_var_attr = TRUE; break;  /* getVarAccessAttributes [6] */
        case 0xab: flags->has_define_nvl   = TRUE; break;  /* defineNVL     [11] */
        case 0xad: flags->has_delete_nvl   = TRUE; break;  /* deleteNVL     [13] */
        default: break;
        }
        if (t == 0xa5) {
            /* write [5] IMPLICIT: variableAccessSpec, listOfData [0] (A0) */
            const guint8 *wr_end = p + l;
            guint8 t2; guint32 l2;
            if (!iccp_ber_read_tl(&p, wr_end, &t2, &l2)) return;
            p += l2;
            if (!iccp_ber_read_tl(&p, wr_end, &t2, &l2)) return;
            if (t2 != 0xa0) return;
            iccp_ber_walk_seq_of(tvb, base, p, l2, flags, walk_ctx, FALSE);
        }
        return;
    }
    if (top_tag == 0xa1) {
        /* confirmed-ResponsePDU: invokeID + confirmedServiceResponse CHOICE */
        guint8 t; guint32 l;
        if (!iccp_ber_read_tl(&p, top_end, &t, &l)) return;
        if (t != 0x02) return;
        p += l;
        if (!iccp_ber_read_tl(&p, top_end, &t, &l)) return;
        switch (t) {
        case 0xa1: flags->has_get_namelist = TRUE; break;
        case 0xa4: flags->has_read         = TRUE; break;
        case 0xa5: flags->has_write        = TRUE; break;
        case 0xa6: flags->has_get_var_attr = TRUE; break;
        case 0xab: flags->has_define_nvl   = TRUE; break;
        case 0xad: flags->has_delete_nvl   = TRUE; break;
        default: break;
        }
        if (t == 0xa4) {
            /* read [4] IMPLICIT: optional varAccessSpec, listOfAccessResult [1] (A1) */
            const guint8 *rd_end = p + l;
            /* Walk forward until we find the A1 listOfAccessResult tag. */
            while (p < rd_end) {
                guint8 t2; guint32 l2;
                const guint8 *before = p;
                if (!iccp_ber_read_tl(&p, rd_end, &t2, &l2)) return;
                if (t2 == 0xa1) {
                    iccp_ber_walk_seq_of(tvb, base, p, l2, flags, walk_ctx, TRUE);
                    return;
                }
                p = before;
                p += /* skip this item: tag + length-of-length + length */
                     ((p[1] < 0x80) ? 2 : 2 + (p[1] & 0x7f)) + l2;
            }
        }
        return;
    }
}

/* -------------------------------------------------------------------------
 * Shared analysis helper
 *
 * Encapsulates walk_tree + attach_decoded_values + classify +
 * conversation/device state machine + surface gate.  Used by
 * dissect_iccp (read_only=FALSE, mutates state) and the stats
 * callback (read_only=TRUE, no side-effects).
 * ---------------------------------------------------------------------- */

typedef struct {
    iccp_pdu_flags_t    flags;
    iccp_name_scan_t    scan;
    iccp_op_t           op;
    iccp_conv_t        *conv;
    iccp_device_entry_t *dev;
    const char         *dev_sub;
    gboolean            dev_bad_operate;
    gboolean            dev_stale_select;
    iccp_walk_ctx_t     walk_ctx;
    gboolean            surface;
    /* TRUE when the BER walker recovered more points / AccessResult
     * items than walk_tree found in the MMS proto tree. That means
     * Wireshark's MMS dissector aborted mid-list on this frame -- the
     * recursion-depth assertion at packet-mms.c:dissect_mms_Data fired
     * (the bug present in Wireshark 4.2.0 / 4.2.1 / 4.2.2; fixed in
     * 4.2.3 and later). On versions with the upstream fix in place,
     * MMS dissects everything and this flag stays FALSE -- the
     * "Recovered points" subtree we emit is then a parallel view of
     * the same data, not a recovery from a truncated tree. */
    gboolean            mms_truncated;
    /* Diagnostic: per-axis counts seen by walk_tree (MMS proto tree)
     * and by iccp_ber_recover (raw bytes). The truncated flag is true
     * iff any BER count exceeds its tree counterpart. Surfaced in the
     * recovered-subtree header so a mis-detection is debuggable from
     * a screenshot without rebuilding. */
    guint32             tree_ar, tree_str, tree_flt, tree_bs;
    guint32             ber_ar,  ber_str,  ber_flt,  ber_bs;
} iccp_analysis_t;

static gboolean
iccp_analyse_tree(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                  iccp_analysis_t *out, gboolean read_only,
                  wmem_allocator_t *array_scope)
{
    memset(out, 0, sizeof *out);
    if (!tree)
        return FALSE;

    walk_tree(pinfo, tree, &out->flags, &out->scan);

    out->walk_ctx.read_only        = read_only;
    out->walk_ctx.point_values     = wmem_array_new(array_scope, sizeof(gfloat));
    out->walk_ctx.point_validities = wmem_array_new(array_scope, sizeof(guint8));
    out->walk_ctx.point_slots      = wmem_array_new(array_scope, sizeof(guint32));
    out->walk_ctx.point_timestamps = wmem_array_new(array_scope, sizeof(iccp_point_time_t));
    out->walk_ctx.ts_candidates    = wmem_array_new(array_scope, sizeof(iccp_ts_candidate_t));
    /* Wire timestamp of the current frame; used by maybe_synthesise_point
     * to compute iccp.point.timestamp.age = frame_abs_ts - point.timestamp.
     * pinfo->abs_ts is set by Wireshark from the pcap packet header. */
    out->walk_ctx.frame_abs_ts     = pinfo ? pinfo->abs_ts : (nstime_t){0,0};
    if (out->flags.floating_point_count > 0
        || out->flags.bit_string_count   > 0
        || out->flags.structure_count    > 0) {
        proto_tree_children_foreach(tree, attach_decoded_values, &out->walk_ctx);
    }

    /* Recover counts + point values from the BER bytes when MMS gave up
     * mid-list (mms.c:2103 recursion-depth assertion). On frames where
     * MMS dissected fully the recovery walker observes the same items
     * the proto-tree walker already counted; on frames where MMS aborted
     * it fills in the rest of the SEQUENCE OF Data.
     *
     * Walk into temporaries, then merge into the main flags/walk_ctx via
     * max-replace: BER counts win when they're larger (canonical, derived
     * from raw bytes), and the BER point arrays replace the tree-derived
     * ones when they hold more values. The proto-tree path stays the sole
     * driver for Point #N synthetic rows in the proto tree -- BER walker
     * does not mutate the tree. */
    {
        iccp_pdu_flags_t ber_flags;
        iccp_walk_ctx_t  ber_ctx;
        memset(&ber_flags, 0, sizeof ber_flags);
        memset(&ber_ctx,   0, sizeof ber_ctx);
        ber_ctx.point_values     = wmem_array_new(array_scope, sizeof(gfloat));
        ber_ctx.point_validities = wmem_array_new(array_scope, sizeof(guint8));
        ber_ctx.point_slots      = wmem_array_new(array_scope, sizeof(guint32));
        ber_ctx.ts_candidates    = wmem_array_new(array_scope, sizeof(iccp_ts_candidate_t));
        /* Make the BER walker emit hidden iccp.point.value /
         * iccp.quality items into the same tree we were given. Hidden
         * means they don't show in the proto tree pane (the visible
         * Point #N rows from attach_decoded_values handle that), but
         * they ARE filterable -- which is what makes
         * `iccp.point.value > 0` and `AVG(iccp.point.value)` work in
         * the GUI's filter scan and I/O Graphs even when the tree is
         * in non-visible mode and MMS items are faked away. */
        ber_ctx.hidden_tree = tree;
        iccp_ber_recover(tvb, &ber_flags, &ber_ctx);

        /* Detect MMS truncation by comparing what walk_tree found in
         * the MMS proto tree vs what the BER walker found in the raw
         * bytes. If BER reports more access results / floats than the
         * tree path saw, MMS aborted mid-list -- the recursion-depth
         * bug in Wireshark <= 4.2.2's dissect_mms_Data fired. On
         * Wireshark 4.2.3+ the bug is fixed, the tree has every
         * AccessResult, and this flag stays FALSE. */
        out->tree_ar  = out->flags.access_result_count;
        out->tree_str = out->flags.structure_count;
        out->tree_flt = out->flags.floating_point_count;
        out->tree_bs  = out->flags.bit_string_count;
        out->ber_ar   = ber_flags.access_result_count;
        out->ber_str  = ber_flags.structure_count;
        out->ber_flt  = ber_flags.floating_point_count;
        out->ber_bs   = ber_flags.bit_string_count;
        if (ber_flags.access_result_count   > out->flags.access_result_count   ||
            ber_flags.floating_point_count  > out->flags.floating_point_count  ||
            ber_flags.bit_string_count      > out->flags.bit_string_count      ||
            ber_flags.structure_count       > out->flags.structure_count) {
            out->mms_truncated = TRUE;
        }

        #define ICCP_MAX_FIELD(f)  do { \
            if (ber_flags.f > out->flags.f) out->flags.f = ber_flags.f; \
        } while (0)
        ICCP_MAX_FIELD(access_result_count);
        ICCP_MAX_FIELD(failure_count);
        ICCP_MAX_FIELD(structure_count);
        ICCP_MAX_FIELD(floating_point_count);
        ICCP_MAX_FIELD(bit_string_count);
        ICCP_MAX_FIELD(binary_time_count);
        ICCP_MAX_FIELD(visible_string_count);
        ICCP_MAX_FIELD(octet_string_count);
        ICCP_MAX_FIELD(utc_time_count);
        ICCP_MAX_FIELD(generalized_time_count);
        ICCP_MAX_FIELD(real_count);
        ICCP_MAX_FIELD(bcd_count);
        ICCP_MAX_FIELD(mms_string_count);
        #undef ICCP_MAX_FIELD

        /* Op-detection booleans set by iccp_ber_recover from the PDU's
         * top-level + inner CHOICE tags. walk_tree derives the same
         * booleans from MMS proto-tree fields, but in Wireshark's
         * two-pass filter mode (which the GUI uses for display
         * filters) the second pass dissects with a reduced wanted-
         * fields set and MMS items aren't kept in the tree. Without
         * these booleans, classify_operation returns ICCP_OP_NONE,
         * the surface gate fails, and the iccp tree is never built --
         * which is exactly the symptom of the GUI's `iccp` filter
         * matching nothing while the per-frame iccp tree displays
         * fine on a clicked frame. OR-merge from BER so either path
         * sets the flag. */
        #define ICCP_OR_FIELD(f)  do { \
            if (ber_flags.f) out->flags.f = TRUE; \
        } while (0)
        ICCP_OR_FIELD(has_initiate_req);
        ICCP_OR_FIELD(has_initiate_resp);
        ICCP_OR_FIELD(has_conclude_req);
        ICCP_OR_FIELD(has_conclude_resp);
        ICCP_OR_FIELD(has_reject);
        ICCP_OR_FIELD(has_info_report);
        ICCP_OR_FIELD(has_confirmed_req);
        ICCP_OR_FIELD(has_confirmed_resp);
        ICCP_OR_FIELD(has_confirmed_err);
        ICCP_OR_FIELD(has_read);
        ICCP_OR_FIELD(has_write);
        ICCP_OR_FIELD(has_get_namelist);
        ICCP_OR_FIELD(has_get_var_attr);
        ICCP_OR_FIELD(has_define_nvl);
        ICCP_OR_FIELD(has_delete_nvl);
        #undef ICCP_OR_FIELD

        guint ber_pv_n = wmem_array_get_count(ber_ctx.point_values);
        guint tree_pv_n = wmem_array_get_count(out->walk_ctx.point_values);
        if (ber_pv_n > tree_pv_n) {
            out->walk_ctx.point_values = ber_ctx.point_values;
            /* Also take BER's per-PDU scalar histograms. The proto-tree
             * walker's counters are zero when MMS aborted (which is
             * exactly when the BER walker fills in for it); without
             * this merge the count-axis stats (Point quality,
             * Point CurrentSource, Points per Transfer Set) read
             * zero on every truncated frame even though the float /
             * bit-string arrays are correct. */
            out->walk_ctx.points_valid       = ber_ctx.points_valid;
            out->walk_ctx.points_held        = ber_ctx.points_held;
            out->walk_ctx.points_suspect     = ber_ctx.points_suspect;
            out->walk_ctx.points_notvalid    = ber_ctx.points_notvalid;
            out->walk_ctx.points_telemetered = ber_ctx.points_telemetered;
            out->walk_ctx.points_calculated  = ber_ctx.points_calculated;
            out->walk_ctx.points_entered     = ber_ctx.points_entered;
            out->walk_ctx.points_estimated   = ber_ctx.points_estimated;
            /* point_index = how many points we counted; align with
             * the merged array length so ti2->point_count reflects
             * what was actually decoded (BER recovery doesn't
             * increment point_index per-leaf). */
            out->walk_ctx.point_index        = ber_pv_n;
        }
        guint ber_ps_n = wmem_array_get_count(ber_ctx.point_slots);
        guint tree_ps_n = wmem_array_get_count(out->walk_ctx.point_slots);
        if (ber_ps_n > tree_ps_n) {
            out->walk_ctx.point_slots = ber_ctx.point_slots;
        }
        guint ber_pq_n = wmem_array_get_count(ber_ctx.point_validities);
        guint tree_pq_n = wmem_array_get_count(out->walk_ctx.point_validities);
        if (ber_pq_n > tree_pq_n) {
            out->walk_ctx.point_validities = ber_ctx.point_validities;
        }
        /* Carry through the data-set reference parsed from
         * variableAccessSpecification.variableListName. The proto-tree
         * walker doesn't extract this -- only the BER walker does. */
        if (ber_ctx.ds_domain && !out->walk_ctx.ds_domain)
            out->walk_ctx.ds_domain = ber_ctx.ds_domain;
        if (ber_ctx.ds_item && !out->walk_ctx.ds_item)
            out->walk_ctx.ds_item   = ber_ctx.ds_item;
        /* Same for the Transfer_Set_Time_Stamp candidates -- only the
         * BER walker captures slot-level integers. Use BER's array
         * when it has more entries (canonical, derived from raw
         * bytes), mirroring the merge policy applied to point arrays
         * just above. */
        if (ber_ctx.ts_candidates) {
            guint ber_tc_n  = wmem_array_get_count(ber_ctx.ts_candidates);
            guint tree_tc_n = out->walk_ctx.ts_candidates
                ? wmem_array_get_count(out->walk_ctx.ts_candidates) : 0;
            if (ber_tc_n > tree_tc_n) {
                out->walk_ctx.ts_candidates = ber_ctx.ts_candidates;
            }
        }
    }

    out->op = classify_operation(&out->flags);

    out->conv = iccp_conv_get(pinfo, !read_only);
    if (!out->conv && !read_only)
        return FALSE;

    /* Association tracking (write path only). */
    if (!read_only && out->conv) {
        if (out->op == ICCP_OP_ASSOC_REQ || out->op == ICCP_OP_ASSOC_RESP) {
            if (out->conv->state == ICCP_ASSOC_NONE) {
                out->conv->state          = ICCP_ASSOC_CANDIDATE;
                out->conv->initiate_frame = pinfo->num;
            }
        }
        if (out->scan.matched && out->conv->state != ICCP_ASSOC_CONFIRMED) {
            out->conv->state           = ICCP_ASSOC_CONFIRMED;
            out->conv->confirmed_frame = pinfo->num;
            g_strlcpy(out->conv->confirmation_name, out->scan.matched_name,
                      sizeof out->conv->confirmation_name);
            out->conv->confirmation_cb = out->scan.matched->cb;
        }
    }

    /* Device Control state machine (Block 5). */
    if (out->scan.matched && out->scan.matched->cb == 5
        && out->scan.matched_name) {
        out->dev_sub = iccp_device_subop(out->scan.matched_name);
        if (out->dev_sub) {
            char base[64];
            iccp_device_base_name(out->scan.matched_name, base, sizeof base);
            out->dev = iccp_device_lookup(pinfo, base, !read_only);
            if (out->dev && !read_only) {
                conversation_t *conv = find_conversation_pinfo(pinfo, 0);
                guint32 conv_idx = conv ? conv->conv_index : 0;
                if (strcmp(out->dev_sub, "Select") == 0) {
                    out->dev->state             = ICCP_DEV_SELECTED;
                    out->dev->select_frame      = pinfo->num;
                    out->dev->select_conv_index = conv_idx;
                } else if (strcmp(out->dev_sub, "SBO-Operate") == 0) {
                    if (out->dev->state != ICCP_DEV_SELECTED)
                        out->dev_bad_operate = TRUE;
                    else if (pinfo->num - out->dev->select_frame > 10000)
                        out->dev_stale_select = TRUE;
                    out->dev->state = ICCP_DEV_OPERATED;
                } else if (strcmp(out->dev_sub, "Cancel") == 0) {
                    out->dev->state = ICCP_DEV_IDLE;
                }
            }
        }
    }

    /* Surface gate. DefineNVL request/response surface unconditionally
     * because (a) they're significant ICCP setup PDUs worth showing under
     * the iccp tree even when no naming pattern matched, and (b) the
     * Define-NVL request carries the slot->name binding we auto-extract
     * for iccp.point.name -- if the surface gate hides it, dissect_iccp
     * returns 0 before our capture hook runs and the auto-DSD map stays
     * empty for the rest of the capture. */
    out->surface =
        (out->conv && out->conv->state == ICCP_ASSOC_CONFIRMED)
        || out->op == ICCP_OP_ASSOC_REQ
        || out->op == ICCP_OP_ASSOC_RESP
        || out->op == ICCP_OP_CONCLUDE_REQ
        || out->op == ICCP_OP_CONCLUDE_RESP
        || out->op == ICCP_OP_INFORMATION_REPORT
        || out->op == ICCP_OP_READ_RESP
        || out->op == ICCP_OP_WRITE_RESP
        || out->op == ICCP_OP_DEFINE_NVL_REQ
        || out->op == ICCP_OP_DEFINE_NVL_RESP
        || out->scan.matched != NULL;

    return out->surface;
}

/* Build and queue the tap_info for the iccp tap. Idempotent per frame:
 * uses ICCP_TAP_QUEUED_KEY in the per-packet proto-data store so
 * multiple call-sites (OID wrapper, post-dissector) cannot double-queue.
 *
 * Note: the stats callback (iccp_stats_tree_packet) is now self-
 * sufficient -- it re-derives all data from edt->tree via
 * iccp_analyse_tree(read_only=TRUE). The tap_info queued here serves
 * external Lua / custom tap consumers only.
 *
 * Allocation strategy: the iccp_tap_info_t and its volatile string
 * fields (object_name, set_name, domain_id) live in wmem_file_scope.
 * iccp_op_str / scan->matched->category / iccp_scope_str / dev_sub /
 * dev->name are either string literals or already in wmem_file_scope
 * and don't need duplicating. The per-point arrays live in the
 * caller's array_scope (pinfo->pool from dissect_iccp); external
 * listeners must copy within their callback. */
static void
iccp_emit_tap(packet_info *pinfo,
              iccp_op_t op,
              iccp_conv_t *info,
              const iccp_name_scan_t *scan,
              iccp_device_entry_t *dev,
              const char *dev_sub,
              const iccp_pdu_flags_t *flags,
              const iccp_walk_ctx_t *walk_ctx)
{
    if (p_get_proto_data(pinfo->pool, pinfo, proto_iccp, ICCP_TAP_QUEUED_KEY))
        return;

    /* Idempotent across retaps: if we already saved good tap data from
     * a previous pass (the initial file load where COTP/Session
     * reassembly works), re-queue it instead of creating new data from
     * what might be a partial MMS dissection.
     * p_get_proto_data with wmem_file_scope persists across retaps. */
    iccp_tap_info_t *saved = (iccp_tap_info_t *)p_get_proto_data(
        wmem_file_scope(), pinfo, proto_iccp, ICCP_TAP_SAVED_KEY);
    if (saved) {
        if (have_tap_listener(proto_iccp_tap))
            tap_queue_packet(proto_iccp_tap, pinfo, saved);
        p_add_proto_data(pinfo->pool, pinfo, proto_iccp,
                         ICCP_TAP_QUEUED_KEY, GINT_TO_POINTER(1));
        return;
    }

    /* First pass: create, save, and queue the tap data. */
    iccp_tap_info_t *ti2 = wmem_new0(wmem_file_scope(), iccp_tap_info_t);
    ti2->op           = (int)op;
    ti2->op_str       = iccp_op_str(op);
    ti2->assoc_state  = (int)info->state;
    if (scan->matched) {
        ti2->cb              = scan->matched->cb;
        ti2->object_category = scan->matched->category;
        ti2->object_name     = scan->matched_name
                             ? wmem_strdup(wmem_file_scope(), scan->matched_name)
                             : NULL;
    }
    if (dev) {
        ti2->device_name  = dev->name;
        ti2->device_state = (int)dev->state;
        ti2->device_sub   = dev_sub;
    }
    if (flags->access_result_count > 0
        && (op == ICCP_OP_INFORMATION_REPORT
         || op == ICCP_OP_READ_RESP
         || op == ICCP_OP_WRITE_RESP)) {
        ti2->report_points     = flags->access_result_count;
        ti2->report_failure    = flags->failure_count;
        ti2->report_success    = (flags->failure_count <= flags->access_result_count)
                               ? (flags->access_result_count - flags->failure_count) : 0;
        ti2->report_structured = (flags->structure_count > 0);
    }
    {
        const char *raw_set = scan->matched_name ? scan->matched_name : scan->first_name;
        ti2->set_name = raw_set ? wmem_strdup(wmem_file_scope(), raw_set) : NULL;
    }
    ti2->scope     = iccp_scope_str(scan->scope);
    ti2->domain_id = scan->domain_id
                   ? wmem_strdup(wmem_file_scope(), scan->domain_id)
                   : NULL;
    ti2->point_count       = walk_ctx->point_index;
    ti2->points_valid      = walk_ctx->points_valid;
    ti2->points_held       = walk_ctx->points_held;
    ti2->points_suspect    = walk_ctx->points_suspect;
    ti2->points_notvalid   = walk_ctx->points_notvalid;
    ti2->points_telemetered = walk_ctx->points_telemetered;
    ti2->points_calculated  = walk_ctx->points_calculated;
    ti2->points_entered     = walk_ctx->points_entered;
    ti2->points_estimated   = walk_ctx->points_estimated;
    ti2->point_value_min   = walk_ctx->v_min;
    ti2->point_value_max   = walk_ctx->v_max;
    ti2->point_value_sum   = walk_ctx->v_sum;
    ti2->has_point_values  = walk_ctx->has_value;
    /* Copy per-point arrays into file scope so they survive retaps.
     * The caller's arrays live in pinfo->pool and would be freed. */
    if (walk_ctx->point_values && wmem_array_get_count(walk_ctx->point_values) > 0) {
        guint n = wmem_array_get_count(walk_ctx->point_values);
        ti2->point_values_arr = wmem_array_new(wmem_file_scope(), sizeof(gfloat));
        wmem_array_append(ti2->point_values_arr,
                          wmem_array_index(walk_ctx->point_values, 0), n);
    }
    if (walk_ctx->point_validities && wmem_array_get_count(walk_ctx->point_validities) > 0) {
        guint n = wmem_array_get_count(walk_ctx->point_validities);
        ti2->point_validities_arr = wmem_array_new(wmem_file_scope(), sizeof(guint8));
        wmem_array_append(ti2->point_validities_arr,
                          wmem_array_index(walk_ctx->point_validities, 0), n);
    }
    /* Mirror slot indices into file-scope storage. Only populated by the
     * BER walker (case 0x87 floating-point appends one slot per numeric
     * point); the proto-tree walker leaves point_slots empty, in which
     * case the count check at stats-tree time prevents indexing past
     * the end of this array. */
    if (walk_ctx->point_slots && wmem_array_get_count(walk_ctx->point_slots) > 0) {
        guint n = wmem_array_get_count(walk_ctx->point_slots);
        ti2->point_slots_arr = wmem_array_new(wmem_file_scope(), sizeof(guint32));
        wmem_array_append(ti2->point_slots_arr,
                          wmem_array_index(walk_ctx->point_slots, 0), n);
    }

    /* Always save in file scope so retaps find good first-pass data,
     * even if no tap listener is active yet (the GUI registers the
     * stats_tree listener only when the user opens Statistics > ICCP). */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_iccp,
                     ICCP_TAP_SAVED_KEY, ti2);
    /* Only queue to the tap if there's actually a listener. */
    if (have_tap_listener(proto_iccp_tap))
        tap_queue_packet(proto_iccp_tap, pinfo, ti2);
    /* Mark in pinfo->pool to prevent double-queue within same pass. */
    p_add_proto_data(pinfo->pool, pinfo, proto_iccp,
                     ICCP_TAP_QUEUED_KEY, GINT_TO_POINTER(1));
}

/* OID-level wrapper around the MMS dissector.
 *
 * Architectural reason for this code path (HANDOVER section 4):
 * post-dissectors run AFTER the column / layer-list snapshot the
 * Wireshark GUI takes for each frame, so when this plugin lived
 * purely as a post-dissector the GUI's Protocol column kept showing
 * "MMS/IEC61850" instead of "ICCP", the Info column showed whatever
 * MMS wrote, the iccp display filter took until Ctrl+R to start
 * matching, and the Statistics dialog routinely showed empty axes
 * during live captures because it had snapshotted before our tap
 * fired.
 *
 * To get into the dispatch chain DURING dissection we register
 * ourselves under the canonical MMS abstract-syntax OID
 * (1.0.9506.2.1) using register_ber_oid_dissector_handle. Plugin
 * registration runs after the built-in MMS dissector's own
 * registration, so our handle wins the OID lookup. PRES then calls
 * us instead of MMS, we call MMS via its handle (preserving every
 * MMS proto-tree node our scanner expects), then run the same
 * analysis the post-dissector did but during dissection. The
 * resulting layer chain is ...:pres:iccp with mms hung underneath
 * us, the GUI columns reflect ICCP from the start, and stats
 * accumulate as packets arrive without depending on retap timing.
 *
 * The post-dissector remains registered as a fallback for captures
 * where MMS dispatches via something other than PRES OID lookup
 * (e.g., the MMS heuristic dissector on COTP for substations that
 * skip PRES). The de-dup flag in dissect_iccp prevents double-
 * counting when both paths fire on the same frame. */
static int
iccp_dispatch_via_oid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int consumed = 0;
    /* MMS's listOfAccessResult / listOfData walker hits a recursion-depth
     * assertion in epan/dissectors/packet-mms.c:2103 once a SEQUENCE OF
     * Data has more than ~2 items. The assertion throws DissectorError,
     * which Wireshark's outer dispatcher catches and *appends* the bug
     * text to col_info. Without TRY/CATCH here, that exception unwinds
     * past us and our analysis never runs for the affected frame.
     * Catching it lets us:
     *   - run the BER recovery walker on the full PDU bytes (recovers
     *     floats / quality bytes / counts past the bug threshold)
     *   - clear the bug text out of col_info and write a clean ICCP
     *     summary in its place
     *   - let the post-dissector pass be skipped via ICCP_PFRAME_DONE_KEY */
    gboolean mms_aborted = FALSE;
    if (mms_handle) {
        TRY {
            consumed = call_dissector_only(mms_handle, tvb, pinfo, tree, data);
        }
        CATCH(DissectorError) {
            mms_aborted = TRUE;
        }
        ENDTRY;
    }
    if (consumed <= 0) {
        consumed = tvb_captured_length(tvb);
    }
    if (mms_aborted) {
        /* The CATCH ate the exception, but Wireshark's expert-info path
         * had already poked the bug message into col_info before the
         * stack unwound. Drop it so dissect_iccp's col_append below
         * starts from a clean slate. */
        col_set_writable(pinfo->cinfo, COL_INFO, TRUE);
        col_clear_fence(pinfo->cinfo, COL_INFO);
        col_clear(pinfo->cinfo, COL_INFO);
    }

    /* Override the Protocol column unconditionally, REGARDLESS of whether
     * `tree` is non-NULL. The Wireshark GUI's first-pass packet-list
     * render passes tree=NULL as a performance optimization (even with
     * a TL_REQUIRES_PROTO_TREE tap on "frame"), which makes dissect_iccp
     * below bail on its !tree guard before its own col_set_str runs.
     * Doing the column write here -- in the OID-level wrapper, with the
     * full pinfo context but no tree dependency -- makes the column
     * read "ICCP" on every frame the wrapper fires, including the
     * first-pass scan that populates the packet list at file open.
     *
     * The fence locks the column so a second MMS dispatch on a
     * reassembled segment, or any other late writer, can't revert it
     * to "MMS/IEC61850". */
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, TRUE);
    col_clear_fence(pinfo->cinfo, COL_PROTOCOL);
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICCP");
    col_set_fence(pinfo->cinfo, COL_PROTOCOL);

    /* Run the existing analysis. dissect_iccp checks the de-dup flag
     * at entry so we mark the frame AFTER calling it -- the flag means
     * "post-dissector skip me, the OID-level wrapper handled this". */
    dissect_iccp(tvb, pinfo, tree, data);
    p_add_proto_data(pinfo->pool, pinfo, proto_iccp, ICCP_PFRAME_DONE_KEY,
                     GINT_TO_POINTER(1));

    return consumed;
}

static int
dissect_iccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* De-duplicate vs the OID-level wrapper. iccp_dispatch_via_oid
     * runs during dissection (PRES->MMS->us via the BER OID dispatcher)
     * and processes the frame fully; the post-dissector hook then
     * fires later with the same frame, so we'd otherwise tap-queue
     * twice and double every count. The wrapper marks each frame in
     * pinfo proto-data; we early-out here when it's set. */
    if (p_get_proto_data(pinfo->pool, pinfo, proto_iccp, ICCP_PFRAME_DONE_KEY))
        return tvb_captured_length(tvb);

    if (!proto_is_frame_protocol(pinfo->layers, "mms"))
        return 0;
    if (!tree)
        return 0;

    iccp_analysis_t a;
    if (!iccp_analyse_tree(pinfo, tree, tvb, &a, FALSE, pinfo->pool))
        return 0;

    /* On Define-NVL requests, capture the (listDomain, listName) and
     * ordered variable items into the auto-DSD map so subsequent
     * InformationReports get slot->name mapping without manual UAT
     * entry. Idempotent on retap (same bytes -> same content). */
    if (a.op == ICCP_OP_DEFINE_NVL_REQ)
        iccp_dsd_capture(tvb, pinfo);

    /* Re-enable writes (MMS / IEC61850 may have frozen them), clear
     * any fence (a fence forces append instead of replace), then
     * set the Protocol column. Wireshark's call_dissector dispatch
     * for post-dissectors already adds "iccp" to pinfo->layers, so
     * we don't push it ourselves. */
    /* Re-enable writes; clear any fence on COL_PROTOCOL so we can
     * replace "MMS/IEC61850" with "ICCP" rather than appending; do
     * NOT clear COL_INFO -- MMS's info string ("InformationReport"
     * etc.) is useful context, and we append onto it below.
     * Clearing it loses MMS's text in the GUI even though our
     * subsequent append never reaches the GUI's column cache. */
    col_set_writable(pinfo->cinfo, -1,           TRUE);
    col_set_writable(pinfo->cinfo, COL_INFO,     TRUE);
    /* COL_PROTOCOL was already set + fenced by iccp_dispatch_via_oid in
     * the OID-wrapper path so the GUI's first-pass packet-list render
     * (which passes tree=NULL and would have bailed before reaching us)
     * still gets the right column. The fence is in place; nothing here
     * needs to write COL_PROTOCOL again. */

    /* Info column: <Op> on <Object>: <Name> */
    {
        const char *op_str = iccp_op_str(a.op);
        if (op_str && a.scan.matched) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ",
                                "ICCP %s [%s: %s]",
                                op_str, a.scan.matched->category, a.scan.matched_name);
        } else if (op_str) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ",
                                "ICCP %s", op_str);
        } else if (a.scan.matched) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ",
                                "ICCP %s: %s",
                                a.scan.matched->category, a.scan.matched_name);
        } else {
            col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", "ICCP");
        }
    }

    /* Proto tree. */
    proto_item *ti    = proto_tree_add_item(tree, proto_iccp, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(ti);
    proto_tree *itree = proto_item_add_subtree(ti, ett_iccp);

    const char *state_str =
        a.conv->state == ICCP_ASSOC_CONFIRMED ? "Confirmed ICCP" :
        a.conv->state == ICCP_ASSOC_CANDIDATE ? "Candidate (Initiate seen)" :
        "Unknown";
    proto_item *state_it = proto_tree_add_string(itree, hf_iccp_association_state,
                                                 tvb, 0, 0, state_str);
    proto_item_set_generated(state_it);

    const char *display_name =
        a.scan.matched_name            ? a.scan.matched_name :
        a.scan.first_name              ? a.scan.first_name   :
        a.conv->confirmation_name[0]   ? a.conv->confirmation_name :
                                         NULL;
    if (display_name) {
        proto_item *nit = proto_tree_add_string(itree, hf_iccp_object_name,
                                                tvb, 0, 0, display_name);
        proto_item_set_generated(nit);
    }

    const char *op_str = iccp_op_str(a.op);
    if (op_str) {
        proto_item *oit = proto_tree_add_string(itree, hf_iccp_operation,
                                                tvb, 0, 0, op_str);
        proto_item_set_generated(oit);
    }

    if (a.scan.matched) {
        proto_item *cit = proto_tree_add_string(itree, hf_iccp_object_category,
                                                tvb, 0, 0, a.scan.matched->category);
        proto_item_set_generated(cit);
        proto_item *cb_it = proto_tree_add_uint(itree, hf_iccp_conformance_block,
                                                tvb, 0, 0, a.scan.matched->cb);
        proto_item_set_generated(cb_it);
        expert_add_info(pinfo, cit, &ei_iccp_object_seen);
    }

    {
        const char *sc = iccp_scope_str(a.scan.scope);
        if (sc) {
            proto_item *sit = proto_tree_add_string(itree, hf_iccp_scope,
                                                    tvb, 0, 0, sc);
            proto_item_set_generated(sit);
        }
        if (a.scan.scope == ICCP_SCOPE_BILATERAL && a.scan.domain_id) {
            proto_item *dit = proto_tree_add_string(itree, hf_iccp_domain,
                                                    tvb, 0, 0, a.scan.domain_id);
            proto_item_set_generated(dit);
        }
    }

    if (a.op == ICCP_OP_ASSOC_REQ || a.op == ICCP_OP_ASSOC_RESP) {
        expert_add_info(pinfo, ti, &ei_iccp_association_seen);
    }
    if (a.op == ICCP_OP_INFORMATION_REPORT) {
        expert_add_info(pinfo, ti, &ei_iccp_info_report);
    }

    if (a.flags.access_result_count > 0
        && (a.op == ICCP_OP_INFORMATION_REPORT
         || a.op == ICCP_OP_READ_RESP
         || a.op == ICCP_OP_WRITE_RESP)) {
        proto_item *pit = proto_tree_add_uint(itree, hf_iccp_report_points,
                                              tvb, 0, 0, a.flags.access_result_count);
        proto_item_set_generated(pit);
        guint32 succ = (a.flags.failure_count <= a.flags.access_result_count)
                     ? (a.flags.access_result_count - a.flags.failure_count) : 0;
        proto_item *sit = proto_tree_add_uint(itree, hf_iccp_report_success,
                                              tvb, 0, 0, succ);
        proto_item_set_generated(sit);
        proto_item *fit = proto_tree_add_uint(itree, hf_iccp_report_failure,
                                              tvb, 0, 0, a.flags.failure_count);
        proto_item_set_generated(fit);
        gboolean structured = (a.flags.structure_count > 0);
        proto_item *bit = proto_tree_add_boolean(itree, hf_iccp_report_structured,
                                                 tvb, 0, 0, structured);
        proto_item_set_generated(bit);

        char summary[256];
        g_snprintf(summary, sizeof summary,
                   "floats=%u bit-strings=%u binary-times=%u visible-strings=%u "
                   "octet-strings=%u utc-times=%u generalized-times=%u "
                   "reals=%u bcds=%u mms-strings=%u",
                   a.flags.floating_point_count,
                   a.flags.bit_string_count,
                   a.flags.binary_time_count,
                   a.flags.visible_string_count,
                   a.flags.octet_string_count,
                   a.flags.utc_time_count,
                   a.flags.generalized_time_count,
                   a.flags.real_count,
                   a.flags.bcd_count,
                   a.flags.mms_string_count);
        proto_item *sumit = proto_tree_add_string(itree, hf_iccp_report_summary,
                                                  tvb, 0, 0, summary);
        proto_item_set_generated(sumit);

        /* Transfer Set timestamp (per-PDU). The BER walker captured
         * every slot-level 4-byte INTEGER from listOfAccessResult into
         * a.walk_ctx.ts_candidates. Iterate the candidates and promote
         * the one whose DSD-resolved variable name is exactly the
         * TASE.2 spec name "Transfer_Set_Time_Stamp" AND whose value
         * falls in a Y2000..Y2100 Unix-seconds plausibility window
         * (946684800 = 2000-01-01, 4102444800 = 2100-01-01). Failure
         * of either guard at every candidate means there's no Transfer
         * Set timestamp on the wire (e.g. DS_ANA_STATKR_L puts a
         * DSConditions bit-mask at slot 1, with no INTEGER timestamp
         * anywhere); we silently decline. The decoded short-form
         * string is also reused below to annotate each per-point row,
         * mirroring how the paid Kema tool shows the report time next
         * to every point. */
        char pdu_ts_str[32]; pdu_ts_str[0] = '\0';
        guint nc = a.walk_ctx.ts_candidates
            ? wmem_array_get_count(a.walk_ctx.ts_candidates) : 0;
        if (nc > 0) {
            const char *lookup_dom  = a.walk_ctx.ds_domain
                ? a.walk_ctx.ds_domain
                : (a.scan.domain_id ? a.scan.domain_id : "");
            const char *lookup_item = a.walk_ctx.ds_item
                ? a.walk_ctx.ds_item
                : (a.scan.matched_name ? a.scan.matched_name : "");
            for (guint k = 0; k < nc; k++) {
                const iccp_ts_candidate_t *c =
                    (const iccp_ts_candidate_t *)wmem_array_index(
                        a.walk_ctx.ts_candidates, k);
                const char *ts_vname = iccp_dsd_lookup(
                    lookup_dom, lookup_item, c->slot);
                if (!ts_vname
                    || g_strcmp0(ts_vname, "Transfer_Set_Time_Stamp") != 0)
                    continue;
                if (c->raw < 946684800u || c->raw >= 4102444800u)
                    continue;

                nstime_t pdu_ts = { .secs = (time_t)c->raw, .nsecs = 0 };
                proto_item *tsit = proto_tree_add_time(itree,
                                                       hf_iccp_transfer_set_timestamp,
                                                       tvb, 0, 0, &pdu_ts);
                proto_item_set_generated(tsit);
                proto_item *tssit = proto_tree_add_uint(itree,
                                                        hf_iccp_transfer_set_timestamp_slot,
                                                        tvb, 0, 0, c->slot);
                proto_item_set_generated(tssit);
                /* Format as HH:MM:SS UTC for the per-point annotation
                 * below. Short form keeps each Point #N row scannable;
                 * the full timestamp is on the top-level field above
                 * for filtering and IO-graph use. Use the same #ifdef
                 * pattern as iccp_format_point_time so MSVC links. */
                time_t secs = (time_t)c->raw;
                struct tm tmv;
#ifdef _WIN32
                if (gmtime_s(&tmv, &secs) == 0) {
#else
                if (gmtime_r(&secs, &tmv)) {
#endif
                    strftime(pdu_ts_str, sizeof pdu_ts_str,
                             "%H:%M:%S UTC", &tmv);
                }
                break;       /* first valid match wins */
            }
        }

        /* Recovered points subtree. The MMS dissector aborts at item ~2
         * of any SEQUENCE OF Data due to mms.c:2103, so the proto-tree
         * pane only shows 1-2 of the actual N AccessResult items even
         * for reports carrying tens or hundreds of points. The BER
         * walker has the full list in walk_ctx.point_values /
         * point_validities; iterate them here to give the user a
         * visible per-point listing under the iccp tree, since the
         * native MMS subtree is truncated. */
        guint np = a.walk_ctx.point_values
                   ? wmem_array_get_count(a.walk_ctx.point_values)     : 0;
        guint nq = a.walk_ctx.point_validities
                   ? wmem_array_get_count(a.walk_ctx.point_validities) : 0;
        guint ns = a.walk_ctx.point_slots
                   ? wmem_array_get_count(a.walk_ctx.point_slots)      : 0;
        if (np > 0) {
            char header[256];
            if (a.mms_truncated) {
                g_snprintf(header, sizeof header,
                           "Recovered points: %u — MMS truncated this frame "
                           "(tree: AR=%u struct=%u flt=%u bs=%u | BER: AR=%u "
                           "struct=%u flt=%u bs=%u). dissect_mms_Data "
                           "recursion-depth bug, fixed upstream in 4.2.3.",
                           np,
                           a.tree_ar, a.tree_str, a.tree_flt, a.tree_bs,
                           a.ber_ar,  a.ber_str,  a.ber_flt,  a.ber_bs);
            } else {
                g_snprintf(header, sizeof header,
                           "Per-point listing: %u (parallel view of MMS "
                           "listOfAccessResult; counts agree tree=BER: AR=%u "
                           "struct=%u flt=%u bs=%u — iccp.point.* fields "
                           "filterable + I/O-graphable)",
                           np, a.ber_ar, a.ber_str, a.ber_flt, a.ber_bs);
            }
            proto_item *rh = proto_tree_add_string(itree, hf_iccp_note,
                                                   tvb, 0, 0, header);
            proto_item_set_generated(rh);
            proto_tree *rsub = proto_item_add_subtree(rh, ett_iccp_point);
            /* One subtree per recovered point, each carrying filterable
             * children: iccp.point.index (uint), iccp.point.value (double),
             * iccp.point.quality (string). Right-click on any child to
             * apply / build a filter; the values feed I/O graphs via
             * iccp.point.value.
             *
             * A single-line "Point #N: <value> [VALIDITY]" parent row
             * gives a quick visual scan; expand for the structured
             * sub-fields. */
            for (guint i = 0; i < np; i++) {
                gfloat fv = *(gfloat *)wmem_array_index(a.walk_ctx.point_values, i);
                const char *vc_str = "?";
                if (i < nq) {
                    guint8 vc = *(guint8 *)wmem_array_index(a.walk_ctx.point_validities, i);
                    vc_str = (vc == 0) ? "VALID"   :
                             (vc == 1) ? "HELD"    :
                             (vc == 2) ? "SUSPECT" :
                                         "NOT_VALID";
                }
                char line[96];
                g_snprintf(line, sizeof line,
                           "Point #%u: %.6g [%s]", i + 1, (double)fv, vc_str);
                proto_item *pit = proto_tree_add_string(rsub, hf_iccp_point_summary,
                                                        tvb, 0, 0, line);
                proto_item_set_generated(pit);
                proto_tree *psub = proto_item_add_subtree(pit, ett_iccp_point);

                proto_item *xi = proto_tree_add_uint(psub, hf_iccp_point_index,
                                                     tvb, 0, 0, i + 1);
                proto_item_set_generated(xi);
                guint32 slot = (guint32)-1;
                if (i < ns) {
                    slot = *(guint32 *)wmem_array_index(a.walk_ctx.point_slots, i);
                    proto_item *si = proto_tree_add_uint(psub, hf_iccp_point_slot,
                                                         tvb, 0, 0, slot);
                    proto_item_set_generated(si);
                    /* Look up the variable name for this slot. Prefer the
                     * data-set reference parsed out of the report's
                     * variableAccessSpecification.variableListName (set by
                     * iccp_ber_recover) -- that's the authoritative key
                     * the DefineNVL request used. Fall back to the
                     * iccp.domain / iccp.object.name pair when the report
                     * carried an inline listOfVariable instead.
                     * Surfaces as iccp.point.name so analysts can
                     * right-click / Apply as Filter on a meaningful label. */
                    const char *lookup_dom  = a.walk_ctx.ds_domain
                        ? a.walk_ctx.ds_domain
                        : (a.scan.domain_id ? a.scan.domain_id : "");
                    const char *lookup_item = a.walk_ctx.ds_item
                        ? a.walk_ctx.ds_item
                        : (a.scan.matched_name ? a.scan.matched_name : "");
                    const char *vname = iccp_dsd_lookup(
                        lookup_dom, lookup_item, slot);
                    if (vname) {
                        proto_item *ni = proto_tree_add_string(psub, hf_iccp_point_name,
                                                               tvb, 0, 0, vname);
                        proto_item_set_generated(ni);
                        /* Update the parent row text so the name shows
                         * inline without needing to expand. */
                        proto_item_append_text(pit, "  →  %s", vname);
                    }
                }
                /* Annotate the parent row with the per-PDU Transfer Set
                 * timestamp -- but only when this point does NOT carry
                 * its own per-point BinaryTime (RealQTimeTag etc.). The
                 * per-point override is checked below; here we look
                 * ahead at the same array. If both timestamps exist for
                 * the same point, the per-point one wins (it's more
                 * specific) and the per-PDU stamp is only shown at the
                 * top-level iccp.transfer_set.timestamp field. */
                if (pdu_ts_str[0]) {
                    gboolean has_per_point_ts = FALSE;
                    guint nt_chk = a.walk_ctx.point_timestamps
                        ? wmem_array_get_count(a.walk_ctx.point_timestamps) : 0;
                    if (i < nt_chk) {
                        const iccp_point_time_t *pt_chk =
                            (const iccp_point_time_t *)wmem_array_index(
                                a.walk_ctx.point_timestamps, i);
                        has_per_point_ts = (pt_chk->ts.secs != 0
                                            || pt_chk->ts.nsecs != 0
                                            || pt_chk->has_time_only);
                    }
                    if (!has_per_point_ts) {
                        proto_item_append_text(pit, "  @ %s", pdu_ts_str);
                    }
                }
                proto_item *vi = proto_tree_add_double(psub, hf_iccp_point_value,
                                                       tvb, 0, 0, (gdouble)fv);
                proto_item_set_generated(vi);
                proto_item *qi = proto_tree_add_string(psub, hf_iccp_point_quality,
                                                       tvb, 0, 0, vc_str);
                proto_item_set_generated(qi);

                /* Per-point timestamp (TASE.2 RealQTimeTag /
                 * RealQTimeTagExtended). The BER walker appended one
                 * iccp_point_time_t per binary-time leaf, in lock-step
                 * with point_values; only emit if this point actually
                 * has one (zero entries indicate RealQ shape). */
                guint nt = a.walk_ctx.point_timestamps
                    ? wmem_array_get_count(a.walk_ctx.point_timestamps) : 0;
                if (i < nt) {
                    const iccp_point_time_t *pt =
                        (const iccp_point_time_t *)wmem_array_index(
                            a.walk_ctx.point_timestamps, i);
                    if (pt->ts.secs != 0 || pt->ts.nsecs != 0
                        || pt->has_time_only) {
                        proto_item *ti = proto_tree_add_time(psub,
                                                             hf_iccp_point_timestamp,
                                                             tvb, 0, 0, &pt->ts);
                        proto_item_set_generated(ti);
                        if (pt->has_ms_extended) {
                            proto_item *xi2 = proto_tree_add_uint(psub,
                                                                  hf_iccp_point_timestamp_ms_extended,
                                                                  tvb, 0, 0,
                                                                  pt->ms_extended);
                            proto_item_set_generated(xi2);
                        }
                        if (!pt->has_time_only) {
                            nstime_t age;
                            nstime_delta(&age, &pinfo->abs_ts, &pt->ts);
                            proto_item *ai = proto_tree_add_time(psub,
                                                                 hf_iccp_point_timestamp_age,
                                                                 tvb, 0, 0, &age);
                            proto_item_set_generated(ai);
                        }
                        /* Append the timestamp to the collapsed parent
                         * row so analysts can scan the recovered-points
                         * list without expanding every entry. */
                        char tsbuf[40];
                        iccp_format_point_time(tsbuf, sizeof tsbuf, pt);
                        proto_item_append_text(pit, "  @ %s", tsbuf);
                    }
                }
            }
        }
    }

    /* Device sub-tree. */
    if (a.dev) {
        proto_item *dti = proto_tree_add_string(itree, hf_iccp_device_state,
                                                tvb, 0, 0,
                                                a.dev->state == ICCP_DEV_SELECTED ? "Selected" :
                                                a.dev->state == ICCP_DEV_OPERATED ? "Operated" :
                                                "Idle");
        proto_item_set_generated(dti);
        proto_tree *dsub = proto_item_add_subtree(dti, ett_iccp_device);

        if (a.dev_sub) {
            char note[128];
            g_snprintf(note, sizeof note, "Device sub-operation: %s on %s",
                       a.dev_sub, a.dev->name);
            proto_item *nit = proto_tree_add_string(dsub, hf_iccp_note,
                                                    tvb, 0, 0, note);
            proto_item_set_generated(nit);
        }

        if (a.dev_bad_operate) {
            expert_add_info(pinfo, dti, &ei_iccp_device_no_select);
        } else if (a.dev_stale_select) {
            expert_add_info(pinfo, dti, &ei_iccp_device_stale_sel);
        } else if (strcmp(a.dev_sub ? a.dev_sub : "", "SBO-Operate") == 0
                || strcmp(a.dev_sub ? a.dev_sub : "", "Direct-Operate") == 0) {
            expert_add_info(pinfo, dti, &ei_iccp_device_operate);
        }
    }

    iccp_emit_tap(pinfo, a.op, a.conv, &a.scan, a.dev, a.dev_sub, &a.flags, &a.walk_ctx);

    return tvb_captured_length(tvb);
}

/* -------------------------------------------------------------------------
 * Stats tree callbacks
 *
 * Registered as a stats_tree plugin under the name "iccp,tree" so
 * users can run:   tshark -r file.pcap -z iccp,tree
 * and get a hierarchical summary of what the ICCP post-dissector saw.
 * ---------------------------------------------------------------------- */

static void
iccp_stats_tree_init(stats_tree *st)
{
    st_node_ops        = stats_tree_create_node(st, "Operation",          0, STAT_DT_INT, TRUE);
    st_node_categories = stats_tree_create_node(st, "Object category",    0, STAT_DT_INT, TRUE);
    st_node_blocks     = stats_tree_create_node(st, "Conformance Block",  0, STAT_DT_INT, TRUE);
    st_node_assocs     = stats_tree_create_node(st, "Association state",  0, STAT_DT_INT, TRUE);
    st_node_devices    = stats_tree_create_node(st, "Device sub-operation", 0, STAT_DT_INT, TRUE);
    st_node_reports    = stats_tree_create_node(st, "Report outcomes",     0, STAT_DT_INT, TRUE);
    /* Tier 3: per-Transfer-Set point counts. Pivot keyed on
     * scan.matched_name (the variable list / object name); each leaf
     * tallies how many TASE.2 IndicationPoints were carried. */
    st_node_points_set   = stats_tree_create_node(st, "Points per Transfer Set", 0, STAT_DT_INT, TRUE);
    st_node_points_qual  = stats_tree_create_node(st, "Point quality",           0, STAT_DT_INT, TRUE);
    /* Per-IEC 60870-6-802 §8.2.1 CurrentSource: how points were
     * acquired. Highly operational -- a high ESTIMATED count flags
     * unreliable RTUs / failing telemetry channels. */
    st_node_points_source = stats_tree_create_node(st, "Point CurrentSource",     0, STAT_DT_INT, TRUE);
    st_node_points_range = stats_tree_create_node(st, "Point value range",       0, STAT_DT_INT, TRUE);
    /* Tier 5: per-peer activity. Pivot keyed on "src -> dst". Acts as
     * a lightweight ICCP conversation table without the weight of
     * register_conversation_table(). */
    st_node_peers        = stats_tree_create_node(st, "ICCP peers",              0, STAT_DT_INT, TRUE);
    /* TASE.2 name scope: VCC = VMD-global / "public" inside this
     * control center; Bilateral = scoped to a Bilateral Table /
     * peer-pair. Bilateral writes (especially Device_*) are the
     * security-sensitive operations. */
    st_node_scope        = stats_tree_create_node(st, "Operations by scope",     0, STAT_DT_INT, TRUE);

    /* Tier 4: STAT_DT_FLOAT axes. Each tick records a numeric value
     * (point value, point count, ratio, percentage, frame length) so
     * the Wireshark dialog populates the Average / Min Val / Max Val
     * columns alongside Count and Percent. STAT_DT_INT axes above stay
     * count-only by design. */
    st_node_pvalues        = stats_tree_create_node(st, "Point values (all numeric points)",   0, STAT_DT_FLOAT, FALSE);
    st_node_pvalues_qual   = stats_tree_create_node(st, "Point values by validity",            0, STAT_DT_FLOAT, TRUE);
    st_node_pvalues_set    = stats_tree_create_node(st, "Point values by Transfer Set",        0, STAT_DT_FLOAT, TRUE);
    st_node_pvalues_cb     = stats_tree_create_node(st, "Point values by Conformance Block",   0, STAT_DT_FLOAT, TRUE);
    st_node_points_per_pdu = stats_tree_create_node(st, "Points per PDU",                       0, STAT_DT_FLOAT, FALSE);
    st_node_success_ratio  = stats_tree_create_node(st, "Report success ratio per PDU",         0, STAT_DT_FLOAT, FALSE);
    st_node_quality_mix    = stats_tree_create_node(st, "Quality mix per PDU (%)",              0, STAT_DT_FLOAT, TRUE);
    st_node_pdu_sizes      = stats_tree_create_node(st, "PDU sizes (bytes)",                    0, STAT_DT_FLOAT, TRUE);

    /* Opt-in: only materialise the per-point-name axes when the preference
     * is enabled at dialog-open time. Toggling the preference while a stats
     * dialog is open won't re-run init; the user has to close and reopen
     * the dialog (Statistics -> ICCP/Statistics) to pick up the change. */
    if (iccp_pref_stats_per_point_name) {
        st_node_points_byname  = stats_tree_create_node(st,
            "Points by name (per Transfer Set)",       0, STAT_DT_INT,   TRUE);
        st_node_pvalues_byname = stats_tree_create_node(st,
            "Point values by name (per Transfer Set)", 0, STAT_DT_FLOAT, TRUE);
    } else {
        st_node_points_byname  = -1;
        st_node_pvalues_byname = -1;
    }
}

static tap_packet_status
iccp_stats_tree_packet(stats_tree *st,
                       packet_info *pinfo,
                       epan_dissect_t *edt _U_,
                       const void *p,
                       tap_flags_t flags _U_)
{
    /* Read from the saved first-pass tap data. iccp_emit_tap guarantees
     * that p always points to the correct data from the initial file load
     * (when COTP/Session reassembly works), even during GUI retap where
     * multi-segment packets may fail to reassemble. */
    const iccp_tap_info_t *ti = (const iccp_tap_info_t *)p;
    if (!ti)
        return TAP_PACKET_DONT_REDRAW;

    /* Operation axis. */
    if (ti->op_str && *ti->op_str) {
        tick_stat_node(st, "Operation",          0, TRUE);
        tick_stat_node(st, ti->op_str, st_node_ops, FALSE);
    }

    /* Object category axis. */
    if (ti->object_category && *ti->object_category) {
        tick_stat_node(st, "Object category",    0, TRUE);
        tick_stat_node(st, ti->object_category, st_node_categories, FALSE);
    }

    /* Conformance Block axis. */
    if (ti->cb > 0) {
        char cb_label[16];
        g_snprintf(cb_label, sizeof cb_label, "Block %u", ti->cb);
        tick_stat_node(st, "Conformance Block",  0, TRUE);
        tick_stat_node(st, cb_label, st_node_blocks, FALSE);
    }

    /* Association state axis. */
    {
        const char *assoc =
            ti->assoc_state == ICCP_ASSOC_CONFIRMED ? "Confirmed ICCP" :
            ti->assoc_state == ICCP_ASSOC_CANDIDATE ? "Candidate"      :
            "Unknown";
        tick_stat_node(st, "Association state",  0, TRUE);
        tick_stat_node(st, assoc, st_node_assocs, FALSE);
    }

    /* Device sub-operation axis. */
    if (ti->device_sub && *ti->device_sub) {
        tick_stat_node(st, "Device sub-operation", 0, TRUE);
        tick_stat_node(st, ti->device_sub, st_node_devices, FALSE);
    }

    /* Report outcomes axis. */
    if (ti->report_points > 0) {
        tick_stat_node(st, "Report outcomes",    0, TRUE);
        if (ti->report_failure == ti->report_points) {
            tick_stat_node(st, "all-failures",        st_node_reports, FALSE);
        } else if (ti->report_failure == 0) {
            tick_stat_node(st, "all-success",         st_node_reports, FALSE);
        } else {
            tick_stat_node(st, "partial (mixed success/failure)", st_node_reports, FALSE);
        }
        if (ti->report_structured) {
            tick_stat_node(st, "structured (TASE.2-shaped)", st_node_reports, FALSE);
        }
    }

    /* Tier 3: per-Transfer-Set, quality, and value-range buckets. */
    if (ti->point_count > 0) {
        const char *set = (ti->set_name && *ti->set_name) ? ti->set_name : "(unnamed)";
        increase_stat_node(st, "Points per Transfer Set", 0, TRUE,  ti->point_count);
        increase_stat_node(st, set, st_node_points_set, FALSE, ti->point_count);

        guint32 q_total = ti->points_valid + ti->points_held +
                          ti->points_suspect + ti->points_notvalid;
        if (q_total > 0) {
            increase_stat_node(st, "Point quality", 0, TRUE, q_total);
            if (ti->points_valid)
                increase_stat_node(st, "VALID",     st_node_points_qual, FALSE, ti->points_valid);
            if (ti->points_held)
                increase_stat_node(st, "HELD",      st_node_points_qual, FALSE, ti->points_held);
            if (ti->points_suspect)
                increase_stat_node(st, "SUSPECT",   st_node_points_qual, FALSE, ti->points_suspect);
            if (ti->points_notvalid)
                increase_stat_node(st, "NOT_VALID", st_node_points_qual, FALSE, ti->points_notvalid);
        }

        /* CurrentSource histogram. */
        guint32 src_total = ti->points_telemetered + ti->points_calculated
                          + ti->points_entered    + ti->points_estimated;
        if (src_total > 0) {
            increase_stat_node(st, "Point CurrentSource", 0, TRUE, src_total);
            if (ti->points_telemetered)
                increase_stat_node(st, "TELEMETERED", st_node_points_source, FALSE, ti->points_telemetered);
            if (ti->points_calculated)
                increase_stat_node(st, "CALCULATED",  st_node_points_source, FALSE, ti->points_calculated);
            if (ti->points_entered)
                increase_stat_node(st, "ENTERED",     st_node_points_source, FALSE, ti->points_entered);
            if (ti->points_estimated)
                increase_stat_node(st, "ESTIMATED",   st_node_points_source, FALSE, ti->points_estimated);
        }

        if (ti->has_point_values) {
            tick_stat_node(st, "Point value range", 0, TRUE);
            const char *bucket;
            if      (ti->point_value_max < 0)        bucket = "negative";
            else if (ti->point_value_max < 1)        bucket = "0..1 (per-unit)";
            else if (ti->point_value_max < 60)       bucket = "1..60 (Hz / pct)";
            else if (ti->point_value_max < 1000)     bucket = "60..1000";
            else if (ti->point_value_max < 100000)   bucket = "1k..100k";
            else                                      bucket = ">=100k";
            tick_stat_node(st, bucket, st_node_points_range, FALSE);
        }
    }

    /* Tier 5: per-peer pivot. */
    {
        char *src = address_to_str(NULL, &pinfo->src);
        char *dst = address_to_str(NULL, &pinfo->dst);
        char  key[160];
        g_snprintf(key, sizeof key, "%s -> %s", src ? src : "?", dst ? dst : "?");
        tick_stat_node(st, "ICCP peers", 0, TRUE);
        tick_stat_node(st, key, st_node_peers, FALSE);
        wmem_free(NULL, src);
        wmem_free(NULL, dst);
    }

    /* Name scope: VCC vs Bilateral. */
    if (ti->scope && *ti->scope) {
        tick_stat_node(st, "Operations by scope", 0, TRUE);
        tick_stat_node(st, ti->scope, st_node_scope, FALSE);
    }

    /* -- Tier 4: STAT_DT_FLOAT axes (Average / Min Val / Max Val). -- */
    if (ti->point_values_arr && ti->point_validities_arr) {
        const guint n_v = wmem_array_get_count(ti->point_values_arr);
        const guint n_q = wmem_array_get_count(ti->point_validities_arr);
        const guint n   = (n_v < n_q) ? n_v : n_q;
        if (n > 0) {
            const char *set = (ti->set_name && *ti->set_name) ? ti->set_name : "(unnamed)";
            char cb_label[24];
            if (ti->cb > 0) g_snprintf(cb_label, sizeof cb_label, "Block %u", ti->cb);
            else            g_strlcpy(cb_label, "Unclassified", sizeof cb_label);

            for (guint i = 0; i < n; i++) {
                const gfloat v  = *(gfloat *)wmem_array_index(ti->point_values_arr, i);
                const guint8 vc = *(guint8 *)wmem_array_index(ti->point_validities_arr, i);
                const char  *vname = (vc == 0) ? "VALID" :
                                     (vc == 1) ? "HELD"  :
                                     (vc == 2) ? "SUSPECT" : "NOT_VALID";

                avg_stat_node_add_value_float(st, "Point values (all numeric points)", 0, FALSE, v);

                avg_stat_node_add_value_float(st, "Point values by validity", 0,                    TRUE,  v);
                avg_stat_node_add_value_float(st, vname,                      st_node_pvalues_qual, FALSE, v);

                avg_stat_node_add_value_float(st, "Point values by Transfer Set", 0,                   TRUE,  v);
                avg_stat_node_add_value_float(st, set,                            st_node_pvalues_set, FALSE, v);

                avg_stat_node_add_value_float(st, "Point values by Conformance Block", 0,                  TRUE,  v);
                avg_stat_node_add_value_float(st, cb_label,                            st_node_pvalues_cb, FALSE, v);
            }

            /* Opt-in per-point-name axes. Only when the preference was on
             * at dialog-open time (the create_node calls in init are
             * conditional on the same flag). Two-step traversal: nest the
             * Transfer-Set name under the top-level node, then place
             * per-point-name leaves under the Transfer-Set parent using
             * the id the first call returns -- this is how stats_tree
             * supports dynamic 3-level trees without pre-registering every
             * possible parent. Falls back to "slot N (unresolved)" when
             * the slot is known but no name was discovered, and skips
             * the axis entirely when slots aren't parallel to values
             * (proto-tree-only path leaves point_slots empty). */
            if (iccp_pref_stats_per_point_name
                && st_node_points_byname  >= 0
                && st_node_pvalues_byname >= 0
                && ti->point_slots_arr
                && wmem_array_get_count(ti->point_slots_arr) == n) {
                const char *lookup_dom  = ti->domain_id ? ti->domain_id : "";
                const char *lookup_item = (ti->set_name && *ti->set_name)
                                            ? ti->set_name : "";
                char unresolved[32];
                for (guint i = 0; i < n; i++) {
                    const gfloat v_pt = *(gfloat *)wmem_array_index(ti->point_values_arr, i);
                    const guint32 slot = *(guint32 *)wmem_array_index(ti->point_slots_arr, i);
                    const char *vname = iccp_dsd_lookup(lookup_dom, lookup_item, slot);
                    const char *label;
                    if (vname) {
                        label = vname;
                    } else {
                        g_snprintf(unresolved, sizeof unresolved,
                                   "slot %u (unresolved)", slot);
                        label = unresolved;
                    }

                    /* Tick root -> TS -> leaf so the parent rows roll
                     * up totals (counts + avg/min/max) instead of
                     * showing 0 / blank. Same root-then-child pattern
                     * the count axes elsewhere in this file use. */
                    tick_stat_node(st, "Points by name (per Transfer Set)",
                                   0, TRUE);
                    int count_parent = tick_stat_node(st, set,
                                                      st_node_points_byname, TRUE);
                    tick_stat_node(st, label, count_parent, FALSE);

                    avg_stat_node_add_value_float(st,
                        "Point values by name (per Transfer Set)",
                        0, TRUE, v_pt);
                    int float_parent = avg_stat_node_add_value_float(
                        st, set, st_node_pvalues_byname, TRUE, v_pt);
                    avg_stat_node_add_value_float(
                        st, label, float_parent, FALSE, v_pt);
                }
            }
        }
    }

    /* Per-PDU shape distributions. */
    if (ti->report_points > 0) {
        avg_stat_node_add_value_float(st, "Points per PDU", 0, FALSE,
                                      (gfloat)ti->point_count);
        const gfloat ratio = (gfloat)ti->report_success / (gfloat)ti->report_points;
        avg_stat_node_add_value_float(st, "Report success ratio per PDU", 0, FALSE, ratio);
    }

    /* Per-PDU quality mix as percentages. */
    if (ti->point_count > 0) {
        const gfloat total = (gfloat)ti->point_count;
        avg_stat_node_add_value_float(st, "Quality mix per PDU (%)", 0,                  TRUE,  100.0f);
        avg_stat_node_add_value_float(st, "VALID%",     st_node_quality_mix, FALSE, 100.0f * (gfloat)ti->points_valid    / total);
        avg_stat_node_add_value_float(st, "HELD%",      st_node_quality_mix, FALSE, 100.0f * (gfloat)ti->points_held     / total);
        avg_stat_node_add_value_float(st, "SUSPECT%",   st_node_quality_mix, FALSE, 100.0f * (gfloat)ti->points_suspect  / total);
        avg_stat_node_add_value_float(st, "NOT_VALID%", st_node_quality_mix, FALSE, 100.0f * (gfloat)ti->points_notvalid / total);
    }

    /* PDU sizes, with per-Operation breakdown. */
    {
        const gfloat sz = (gfloat)pinfo->fd->pkt_len;
        avg_stat_node_add_value_float(st, "PDU sizes (bytes)", 0, TRUE, sz);
        if (ti->op_str && *ti->op_str)
            avg_stat_node_add_value_float(st, ti->op_str, st_node_pdu_sizes, FALSE, sz);
    }

    return TAP_PACKET_REDRAW;
}

/* -------------------------------------------------------------------------
 * Data Set Definition mapping (UAT)
 *
 * MMS InformationReports identify each value only by its position in
 * listOfAccessResult -- no per-point name on the wire. The mapping
 * "slot -> variable name" lives in the bilateral table / Data Set
 * Definition that the peers negotiated at session setup.
 *
 * If the capture covered the negotiation, our DefineNamedVariableList
 * auto-capture (next section) will populate the mapping automatically.
 * For mid-session captures (the common case for utility operators
 * dropping a tap on a long-lived link), the operator can paste the
 * mapping into the GUI: Edit -> Preferences -> Protocols -> ICCP ->
 * "DSD Mapping". One row per (domain, transfer set, slot, name).
 *
 * Lookup is O(N * rows) per point; we expect a few thousand rows at
 * most (one row per point in a few transfer sets), so a linear scan is
 * fine. If a deployment ends up with tens of thousands of rows, switch
 * to a hash table keyed by (domain, transfer_set).
 * ---------------------------------------------------------------------- */

typedef struct {
    char    *domain;
    char    *transfer_set;
    guint32  slot;          /* must be guint32 -- UAT_DEC_CB_DEF calls ws_strtou32 */
    char    *var_name;
} iccp_dsd_record_t;

static iccp_dsd_record_t *iccp_dsd_records       = NULL;
static guint              iccp_dsd_records_count = 0;

UAT_CSTRING_CB_DEF(iccp_dsd, domain,       iccp_dsd_record_t)
UAT_CSTRING_CB_DEF(iccp_dsd, transfer_set, iccp_dsd_record_t)
UAT_DEC_CB_DEF(    iccp_dsd, slot,         iccp_dsd_record_t)
UAT_CSTRING_CB_DEF(iccp_dsd, var_name,     iccp_dsd_record_t)

static void *
iccp_dsd_copy_cb(void *dst_, const void *src_, size_t len _U_)
{
    iccp_dsd_record_t       *d = (iccp_dsd_record_t *)dst_;
    const iccp_dsd_record_t *s = (const iccp_dsd_record_t *)src_;
    d->domain       = g_strdup(s->domain);
    d->transfer_set = g_strdup(s->transfer_set);
    d->slot         = s->slot;
    d->var_name     = g_strdup(s->var_name);
    return d;
}

static bool
iccp_dsd_update_cb(void *r, char **err)
{
    iccp_dsd_record_t *rec = (iccp_dsd_record_t *)r;
    if (!rec->domain || !*rec->domain) {
        *err = g_strdup("Domain is required");
        return FALSE;
    }
    if (!rec->transfer_set || !*rec->transfer_set) {
        *err = g_strdup("Transfer Set is required");
        return FALSE;
    }
    if (!rec->var_name || !*rec->var_name) {
        *err = g_strdup("Variable Name is required");
        return FALSE;
    }
    return TRUE;
}

static void
iccp_dsd_free_cb(void *r)
{
    iccp_dsd_record_t *rec = (iccp_dsd_record_t *)r;
    g_free(rec->domain);
    g_free(rec->transfer_set);
    g_free(rec->var_name);
}

static uat_field_t iccp_dsd_fields[] = {
    UAT_FLD_CSTRING(iccp_dsd, domain,       "Domain",
        "Bilateral domain (the domainId in domain-specific ObjectName)."),
    UAT_FLD_CSTRING(iccp_dsd, transfer_set, "Transfer Set",
        "Transfer Set / Data Set name (the itemId)."),
    UAT_FLD_DEC(    iccp_dsd, slot,         "Slot",
        "0-based listOfAccessResult slot (matches iccp.point.slot)."),
    UAT_FLD_CSTRING(iccp_dsd, var_name,     "Variable Name",
        "Human-readable name for the point at this slot."),
    UAT_END_FIELDS
};

/* -------------------------------------------------------------------------
 * Auto-discovered DSDs (from DefineNamedVariableList-Request frames seen
 * in the same capture). On every Define-NVL request, walk the BER bytes
 * to extract (listDomain, listName) and the ordered variable items, and
 * persist them into a file-scope map keyed by "domain|listName".
 *
 * iccp_dsd_lookup falls back to this map after the user-supplied UAT,
 * so captures that include the negotiation get slot->name mapping for
 * free; captures that miss it still benefit from manual UAT entries.
 * ---------------------------------------------------------------------- */
static wmem_map_t *iccp_dsd_auto = NULL;   /* "domain|listName" -> wmem_array_t of char* */

/* Read an Identifier (BER VisibleString, tag 0x1a) into a wmem_strdup'd char*. */
static char *
iccp_ber_read_identifier(const guint8 **p, const guint8 *end, wmem_allocator_t *scope)
{
    if (*p >= end) return NULL;
    const guint8 *save = *p;
    guint8 t; guint32 l;
    if (!iccp_ber_read_tl(p, end, &t, &l) || t != 0x1a || (gsize)(end - *p) < l) {
        *p = save;
        return NULL;
    }
    char *s = (char *)wmem_alloc(scope, l + 1);
    memcpy(s, *p, l);
    s[l] = '\0';
    *p += l;
    return s;
}

/* Read an ObjectName: CHOICE { vmd-specific [0] IMPLICIT Identifier,
 *                              domain-specific [1] IMPLICIT SEQUENCE { domainId, itemId },
 *                              aa-specific [2] IMPLICIT Identifier }.
 * Sets *domain_out (NULL for non-domain-specific) and *item_out. */
static gboolean
iccp_ber_read_object_name(const guint8 **p, const guint8 *end,
                          wmem_allocator_t *scope,
                          char **domain_out, char **item_out)
{
    *domain_out = NULL;
    *item_out   = NULL;
    if (*p >= end) return FALSE;
    const guint8 *save = *p;
    guint8 t; guint32 l;
    if (!iccp_ber_read_tl(p, end, &t, &l)) {
        *p = save;
        return FALSE;
    }
    const guint8 *body_end = *p + l;
    if (body_end > end) {
        *p = save;
        return FALSE;
    }
    if (t == 0xa1) {
        /* domain-specific [1] IMPLICIT SEQUENCE { domainId Identifier, itemId Identifier } */
        char *dom  = iccp_ber_read_identifier(p, body_end, scope);
        char *item = iccp_ber_read_identifier(p, body_end, scope);
        *p = body_end;
        if (!dom || !item) return FALSE;
        *domain_out = dom;
        *item_out   = item;
        return TRUE;
    }
    if (t == 0xa0 || t == 0xa2) {
        /* IMPLICIT Identifier — body bytes ARE the visible string. */
        char *s = (char *)wmem_alloc(scope, l + 1);
        memcpy(s, *p, l);
        s[l] = '\0';
        *p = body_end;
        *item_out = s;
        return TRUE;
    }
    *p = body_end;
    return FALSE;
}

/* Capture a DSD from a DefineNamedVariableList-Request PDU. Tolerant:
 * any structural mismatch returns silently. Idempotent across retaps:
 * a pinfo->pool proto-data guard (ICCP_DSD_CAPTURED_KEY) short-circuits
 * the second visit to the same frame, so the auto-DSD map and the
 * Export Objects tap each see one event per Define-NVL on the wire
 * regardless of how many retap cycles Wireshark drives. When pinfo
 * is non-NULL and a tap listener is active on iccp_dsd_eo_tap (the
 * Export Objects listener registered via register_export_object), the
 * function also queues one tap event per successfully parsed DSD --
 * that powers File -> Export Objects -> ICCP. */
static void
iccp_dsd_capture(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!tvb) return;

    /* Idempotency guard. Skip the parse entirely if we've already
     * processed this frame in this pinfo lifetime (= one
     * dissect/retap cycle for the same frame number). The auto map's
     * file-scope strings from the first pass remain valid; not
     * rebuilding avoids leaking memory and avoids re-queuing a
     * duplicate EO tap event. */
    if (pinfo && p_get_proto_data(pinfo->pool, pinfo, proto_iccp,
                                  ICCP_DSD_CAPTURED_KEY)) {
        return;
    }
    gint avail = tvb_captured_length(tvb);
    if (avail < 6) return;
    const guint8 *base = tvb_get_ptr(tvb, 0, avail);
    if (!base) return;
    const guint8 *p = base, *end = base + avail;
    wmem_allocator_t *scope = wmem_file_scope();

    /* confirmed-RequestPDU [0] IMPLICIT */
    guint8 t; guint32 l;
    if (!iccp_ber_read_tl(&p, end, &t, &l) || t != 0xa0) return;
    const guint8 *req_end = p + l;
    if (req_end > end) return;
    /* invokeID INTEGER */
    if (!iccp_ber_read_tl(&p, req_end, &t, &l) || t != 0x02) return;
    p += l;
    /* confirmedServiceRequest CHOICE — defineNamedVariableList = [11] IMPLICIT (0xab) */
    if (!iccp_ber_read_tl(&p, req_end, &t, &l) || t != 0xab) return;
    const guint8 *def_end = p + l;
    if (def_end > req_end) return;

    /* variableListName: ObjectName */
    char *list_dom = NULL, *list_item = NULL;
    if (!iccp_ber_read_object_name(&p, def_end, scope, &list_dom, &list_item)
        || !list_item) {
        return;
    }

    /* listOfVariable [0] IMPLICIT SEQUENCE OF SEQUENCE { variableSpec, alternateAccess [5] OPT } */
    if (!iccp_ber_read_tl(&p, def_end, &t, &l) || t != 0xa0) return;
    const guint8 *lov_end = p + l;
    if (lov_end > def_end) return;

    if (!iccp_dsd_auto) {
        iccp_dsd_auto = wmem_map_new(scope, g_str_hash, g_str_equal);
    }
    char *key = wmem_strdup_printf(scope, "%s|%s",
                                   list_dom ? list_dom : "", list_item);
    /* Always overwrite — the wire definition is the source of truth. */
    wmem_array_t *names = wmem_array_new(scope, sizeof(char *));
    wmem_map_insert(iccp_dsd_auto, key, names);

    /* Iterate item SEQUENCEs. */
    while (p < lov_end) {
        if (!iccp_ber_read_tl(&p, lov_end, &t, &l)) break;
        const guint8 *item_end = p + l;
        if (item_end > lov_end) break;
        if (t != 0x30) { p = item_end; continue; }
        /* variableSpecification CHOICE — name [0] EXPLICIT ObjectName */
        guint8 t2; guint32 l2;
        if (!iccp_ber_read_tl(&p, item_end, &t2, &l2) || t2 != 0xa0) {
            p = item_end; continue;
        }
        const guint8 *name_end = p + l2;
        char *vd = NULL, *vi = NULL;
        if (iccp_ber_read_object_name(&p, name_end, scope, &vd, &vi) && vi) {
            wmem_array_append_one(names, vi);
        }
        p = item_end;
    }

    /* Mark this frame as DSD-captured so a retap (stats Apply, dialog
     * reopen, etc.) doesn't re-parse, re-allocate file-scope strings,
     * or re-queue the EO event. The guard pointer's value is unused;
     * presence is what matters. */
    if (pinfo) {
        p_add_proto_data(pinfo->pool, pinfo, proto_iccp,
                         ICCP_DSD_CAPTURED_KEY, GINT_TO_POINTER(1));
    }

    /* Queue an Export Objects tap event so File -> Export Objects -> ICCP
     * lists this DSD. The slot_names array references the same
     * wmem_file_scope strings already in iccp_dsd_auto -- no copy here;
     * the EO callback g_strdup's into Wireshark-owned storage. Skipped
     * silently if no pinfo (legacy callers) or no listener attached. */
    if (pinfo && have_tap_listener(iccp_dsd_eo_tap)) {
        guint n = wmem_array_get_count(names);
        iccp_dsd_tap_info_t *info = wmem_new0(scope, iccp_dsd_tap_info_t);
        info->pkt_num    = pinfo->num;
        info->domain     = list_dom;
        info->list_name  = list_item;
        info->slot_count = n;
        if (n > 0) {
            info->slot_names = (char **)wmem_alloc(scope, n * sizeof(char *));
            for (guint i = 0; i < n; i++) {
                info->slot_names[i] = *(char **)wmem_array_index(names, i);
            }
        }
        tap_queue_packet(iccp_dsd_eo_tap, pinfo, info);
    }
}

/* Export Objects packet callback. One call per DefineNVL tap event;
 * builds a CSV (slot,var_name) and hands the entry to the EO list. The
 * EO framework owns the entry afterwards and frees fields via g_free,
 * so every string given here must come from GLib allocation. */
static tap_packet_status
eo_iccp_packet_cb(void *tapdata, packet_info *pinfo _U_,
                  epan_dissect_t *edt _U_, const void *data,
                  tap_flags_t flags _U_)
{
    export_object_list_t          *object_list = (export_object_list_t *)tapdata;
    const iccp_dsd_tap_info_t     *info        = (const iccp_dsd_tap_info_t *)data;
    if (!info || !object_list) return TAP_PACKET_DONT_REDRAW;

    /* CSV body: header + one row per slot. Even empty lists get the
     * header so the file isn't zero-length on Save. RFC 4180 escape
     * on the var_name field: wrap in double quotes and double any
     * embedded double quotes whenever the value contains comma,
     * quote, CR or LF. Slot is a guint so never needs quoting. */
    GString *csv = g_string_new("slot,var_name\n");
    for (guint i = 0; i < info->slot_count; i++) {
        const char *vn = info->slot_names[i] ? info->slot_names[i] : "";
        gboolean needs_quoting = (strpbrk(vn, ",\"\r\n") != NULL);
        if (needs_quoting) {
            g_string_append_printf(csv, "%u,\"", i);
            for (const char *p = vn; *p; p++) {
                if (*p == '"') g_string_append(csv, "\"\"");
                else           g_string_append_c(csv, *p);
            }
            g_string_append(csv, "\"\n");
        } else {
            g_string_append_printf(csv, "%u,%s\n", i, vn);
        }
    }

    /* Filename: <domain>__<list_name>.csv (or vmd__<list_name>.csv for
     * VMD-scope lists with no domain). Sanitised through eo_massage_str
     * so path separators / control characters can't sneak into Save. */
    const char *dom_for_fn = (info->domain && *info->domain) ? info->domain : "vmd";
    char *raw_name = g_strdup_printf("%s__%s.csv",
                                     dom_for_fn,
                                     info->list_name ? info->list_name : "list");
    /* eo_massage_str returns a freshly allocated GString; consume it as
     * a g_malloc'd cstring (g_string_free with free_segment=FALSE hands
     * the buffer to GLib's allocator, matching what the EO framework
     * expects). */
    GString *gs = eo_massage_str(raw_name, EXPORT_OBJECT_MAXFILELEN, 0);
    g_free(raw_name);
    char *safe_name = g_string_free(gs, FALSE);

    export_object_entry_t *entry = g_new0(export_object_entry_t, 1);
    entry->pkt_num      = info->pkt_num;
    entry->hostname     = g_strdup(info->domain ? info->domain : "");
    entry->content_type = g_strdup("text/csv");
    entry->filename     = safe_name;     /* ownership transferred */
    entry->payload_len  = (size_t)csv->len;
    entry->payload_data = (guint8 *)g_string_free(csv, FALSE);

    object_list->add_entry(object_list->gui_data, entry);
    return TAP_PACKET_REDRAW;
}

/* Reset the auto-DSD map between files. wmem_file_scope memory is freed
 * by Wireshark on file close; we just need to drop the dangling pointer
 * so the next file builds the map fresh. */
static void
iccp_dsd_auto_reset(void)
{
    iccp_dsd_auto = NULL;
}

/* Look up the variable name for a point. UAT first, then auto-discovered
 * DSDs from on-wire DefineNVL frames. Returns NULL if no mapping. */
static const char *
iccp_dsd_lookup(const char *domain, const char *transfer_set, guint32 slot)
{
    if (!domain || !transfer_set) return NULL;
    /* 1. User-supplied UAT (highest precedence: lets the analyst override
     *    or supplement what was on the wire). */
    for (guint i = 0; i < iccp_dsd_records_count; i++) {
        const iccp_dsd_record_t *r = &iccp_dsd_records[i];
        if (r->slot == slot
            && g_strcmp0(r->domain,       domain)       == 0
            && g_strcmp0(r->transfer_set, transfer_set) == 0) {
            return r->var_name;
        }
    }
    /* 2. Auto-discovered from DefineNamedVariableList-Request frames in
     *    this capture. Slot N -> Nth variable in the declared list. */
    if (iccp_dsd_auto) {
        char key_buf[512];
        g_snprintf(key_buf, sizeof key_buf, "%s|%s", domain, transfer_set);
        wmem_array_t *names = (wmem_array_t *)wmem_map_lookup(iccp_dsd_auto, key_buf);
        if (names && slot < wmem_array_get_count(names)) {
            char **arr = (char **)wmem_array_index(names, 0);
            return arr[slot];
        }
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * Protocol registration
 * ---------------------------------------------------------------------- */

void
proto_register_iccp(void)
{
    static hf_register_info hf[] = {
        { &hf_iccp_association_state,
          { "Association state", "iccp.association.state",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Whether this conversation has been confirmed as ICCP/TASE.2",
            HFILL }
        },
        { &hf_iccp_object_category,
          { "Object category", "iccp.object.category",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "TASE.2 category of the matched MMS object name",
            HFILL }
        },
        { &hf_iccp_object_name,
          { "Object name", "iccp.object.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "The MMS identifier that matched an ICCP naming convention",
            HFILL }
        },
        { &hf_iccp_scope,
          { "Scope", "iccp.scope",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "TASE.2 name scope: VCC = VMD-global (public to this control "
            "center) or Bilateral = scoped to a named domain (the Bilateral "
            "Table both peers share -- typically the high-value access path).",
            HFILL }
        },
        { &hf_iccp_domain,
          { "Bilateral domain", "iccp.domain",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MMS domainId of the Bilateral Table the access is scoped to. "
            "Empty when scope is VCC.",
            HFILL }
        },
        { &hf_iccp_operation,
          { "Operation", "iccp.operation",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MMS operation interpreted in the ICCP context",
            HFILL }
        },
        { &hf_iccp_conformance_block,
          { "Conformance Block", "iccp.cb",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "TASE.2 conformance block that classifies the matched object",
            HFILL }
        },
        { &hf_iccp_device_state,
          { "Device state", "iccp.device.state",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Tracked Block-5 device state (Idle / Selected / Operated)",
            HFILL }
        },
        { &hf_iccp_note,
          { "Note", "iccp.note",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iccp_report_points,
          { "Report points", "iccp.report.point_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of AccessResult items in this report PDU "
            "(one per reported data point)",
            HFILL }
        },
        { &hf_iccp_report_success,
          { "Successful points", "iccp.report.success_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of AccessResult items that decoded successfully",
            HFILL }
        },
        { &hf_iccp_report_failure,
          { "Failed points", "iccp.report.failure_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of AccessResult items that returned a failure "
            "reason (object undefined, access denied, etc.)",
            HFILL }
        },
        { &hf_iccp_report_structured,
          { "Structured TASE.2 data", "iccp.report.structured",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "TRUE when the report points are MMS structures, which is "
            "the canonical shape of a TASE.2 DSConditions report "
            "(value + quality + timestamp + COT per point)",
            HFILL }
        },
        { &hf_iccp_report_summary,
          { "Report data summary", "iccp.report.summary",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Human-readable breakdown of primitive data values present "
            "in the report (floats, bit-strings, binary-times, ...)",
            HFILL }
        },
        { &hf_iccp_value_real,
          { "Decoded float", "iccp.value.real",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "MMS floating-point primitive decoded to IEEE 754 single-"
            "precision. The MMS dissector shows these as raw bytes"
            "because the 1-byte exponent-width prefix is unusual; this "
            "field exposes the actual numeric value.",
            HFILL }
        },
        { &hf_iccp_quality,
          { "Quality (decoded)", "iccp.quality",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "TASE.2 IndicationPoint quality byte (IEC 60870-6-503).",
            HFILL }
        },
        { &hf_iccp_quality_validity,
          { "Validity", "iccp.quality.validity",
            FT_UINT8, BASE_DEC, VALS(iccp_q_validity_vals), ICCP_Q_VALIDITY_MASK,
            NULL, HFILL }
        },
        { &hf_iccp_quality_normal,
          { "NormalValue", "iccp.quality.normal_value",
            FT_BOOLEAN, 8, NULL, ICCP_Q_NORMAL_MASK,
            "Per IEC 60870-6-802 §8.2.1: 1 = NORMAL (point reading is "
            "within its declared normal operating range), 0 = OFF_NORMAL "
            "(reading is outside the normal range -- the SCADA HMI "
            "alarm-triggers on this). Earlier code had this inverted; "
            "the corrected sense matches the TASE.2 spec.",
            HFILL }
        },
        { &hf_iccp_quality_ts_invalid,
          { "Timestamp invalid", "iccp.quality.timestamp_invalid",
            FT_BOOLEAN, 8, NULL, ICCP_Q_TS_INVALID_MASK,
            "1 = the timestamp on this point cannot be trusted.",
            HFILL }
        },
        { &hf_iccp_quality_source,
          { "CurrentSource", "iccp.quality.source",
            FT_UINT8, BASE_DEC, VALS(iccp_q_source_vals), ICCP_Q_SOURCE_MASK,
            "TASE.2 CurrentSource (IEC 60870-6-802 §8.2.1): how the value "
            "was acquired. TELEMETERED = real measurement off the wire; "
            "CALCULATED = derived from other points; ENTERED = manually "
            "keyed by an operator; ESTIMATED = system filled in because "
            "the real value was unavailable. A high ESTIMATED rate "
            "across a Transfer Set indicates an unreliable source RTU "
            "or a degraded link.",
            HFILL }
        },
        { &hf_iccp_quality_summary,
          { "Quality summary", "iccp.quality.summary",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Human-readable digest: VALIDITY / SOURCE / NORMAL / TS_OK",
            HFILL }
        },
        { &hf_iccp_point_summary,
          { "Point", "iccp.point",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "TASE.2 IndicationPoint: value + quality on one line.",
            HFILL }
        },
        { &hf_iccp_point_value,
          { "Value", "iccp.point.value",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "Decoded numeric value of the point. Stored as double so "
            "Wireshark's right-click `field == <displayed>` filter "
            "matches without single-precision rounding mismatch.",
            HFILL }
        },
        { &hf_iccp_point_quality,
          { "Quality", "iccp.point.quality",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Decoded quality flags for the point.",
            HFILL }
        },
        { &hf_iccp_point_index,
          { "Index", "iccp.point.index",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "1-based ordinal among the recovered float points in this "
            "InformationReport. Useful for filtering / I/O graphs but does "
            "not match a TASE.2 Data Set Definition slot when the report "
            "has non-point header items (timestamp, sequence counter).",
            HFILL }
        },
        { &hf_iccp_point_slot,
          { "Slot", "iccp.point.slot",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "0-based position of this point in listOfAccessResult. "
            "Matches the ordinal in the partner's Data Set Definition / "
            "bilateral table documentation, so is the right field to use "
            "when correlating values to variable names.",
            HFILL }
        },
        { &hf_iccp_point_name,
          { "Name", "iccp.point.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Variable name for this slot, looked up in the user-supplied "
            "DSD mapping (Edit -> Preferences -> Protocols -> ICCP -> "
            "DSD Mapping) or in DSDs auto-captured from "
            "DefineNamedVariableList PDUs earlier in the same conversation.",
            HFILL }
        },
        { &hf_iccp_point_timestamp,
          { "Timestamp", "iccp.point.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            "TASE.2 IndicationPoint sample time, decoded from the BinaryTime "
            "field in the point structure (RealQTimeTag = 6-byte BinaryTime6, "
            "RealQTimeTagExtended = 8-byte BinaryTime8 = BinaryTime6 + 2-byte "
            "fractional-millisecond extension). Epoch is 1984-01-01 00:00:00 "
            "UTC per ISO/IEC 9506. Empty on RealQ-shape points (no time field).",
            HFILL }
        },
        { &hf_iccp_point_timestamp_ms_extended,
          { "Timestamp ms-extended", "iccp.point.timestamp.ms_extended",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Raw 16-bit fractional-millisecond field present only on "
            "TASE.2 RealQTimeTagExtended (BinaryTime8) points. Per IEC "
            "60870-6-503 Annex C, units are 1/2^16 of a millisecond, "
            "though some vendors use straight microseconds (0..999) -- "
            "interpret per your peer.",
            HFILL }
        },
        { &hf_iccp_point_timestamp_age,
          { "Timestamp age", "iccp.point.timestamp.age",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "frame.time - iccp.point.timestamp -- how stale this measurement "
            "is relative to when the frame arrived on the wire. Negative "
            "values mean the substation's clock is in the future relative "
            "to the capture host (typical clock-sync issue). Filter on "
            "iccp.point.timestamp.age > 5.0 to find stale data, "
            "iccp.point.timestamp.age < -1.0 for clock skew.",
            HFILL }
        },
        { &hf_iccp_point_state,
          { "State", "iccp.point.state",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "TASE.2 DoubleState (per IEC 60870-6-802 §8.2.2): the 2-bit "
            "state value, decoded as INTERMEDIATE / OFF / ON / INVALID. "
            "OFF / ON typically map to switch / breaker positions; "
            "INTERMEDIATE means in transition (both contacts open or "
            "closed during operation); INVALID means contradictory "
            "feedback (sensor stuck or both contacts asserted). "
            "Populated only on State / StateSupplemental shaped points.",
            HFILL }
        },
        { &hf_iccp_point_state_supplemental,
          { "State supplemental", "iccp.point.state_supplemental",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Raw 8-bit supplemental flag byte from a TASE.2 "
            "StateSupplemental IndicationPoint -- vendor-defined "
            "tag/lock/alarm bits. Interpretation per peer.",
            HFILL }
        },
        { &hf_iccp_point_discrete,
          { "Discrete value", "iccp.point.discrete",
            FT_INT32, BASE_DEC, NULL, 0x0,
            "TASE.2 Discrete IndicationPoint integer value (counters, "
            "set points, mode codes). Distinct from iccp.point.value "
            "which is the floating-point value of Real-shape points.",
            HFILL }
        },
        { &hf_iccp_transfer_set_timestamp,
          { "Transfer Set timestamp", "iccp.transfer_set.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            "Wall-clock UTC the source RTU assigned to the report at "
            "assembly time. Decoded from a slot-level MMS INTEGER whose "
            "DSD variable name is 'Transfer_Set_Time_Stamp'. One value "
            "per InformationReport; applies to every point in the report "
            "unless that point carries its own BinaryTime override.",
            HFILL }
        },
        { &hf_iccp_transfer_set_timestamp_slot,
          { "Transfer Set timestamp slot", "iccp.transfer_set.timestamp.slot",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Which listOfAccessResult slot carried the Transfer Set "
            "timestamp (typically 1, but some DSDs put it at 2).",
            HFILL }
        },
    };

    static gint *ett[] = {
        &ett_iccp,
        &ett_iccp_objects,
        &ett_iccp_device,
        &ett_iccp_value,
        &ett_iccp_quality,
        &ett_iccp_point,
    };

    static ei_register_info ei[] = {
        { &ei_iccp_association_seen,
          { "iccp.association.seen", PI_SEQUENCE, PI_NOTE,
            "ICCP association handshake observed", EXPFILL }
        },
        { &ei_iccp_object_seen,
          { "iccp.object.seen", PI_PROTOCOL, PI_CHAT,
            "ICCP reserved object name matched", EXPFILL }
        },
        { &ei_iccp_info_report,
          { "iccp.inforeport.seen", PI_SEQUENCE, PI_NOTE,
            "ICCP InformationReport (likely Transfer Set)", EXPFILL }
        },
        { &ei_iccp_device_operate,
          { "iccp.device.operate", PI_SECURITY, PI_WARN,
            "ICCP Device Operate -- physical device action requested",
            EXPFILL }
        },
        { &ei_iccp_device_no_select,
          { "iccp.device.no_select", PI_SECURITY, PI_ERROR,
            "ICCP Device Operate without a preceding Select (SBO violation)",
            EXPFILL }
        },
        { &ei_iccp_device_stale_sel,
          { "iccp.device.stale_select", PI_SECURITY, PI_WARN,
            "ICCP Device Operate long after Select -- possible timeout",
            EXPFILL }
        },
    };

    proto_iccp = proto_register_protocol(
        "Inter-Control Center Communications Protocol (ICCP/TASE.2)",
        "ICCP",
        "iccp"
    );

    proto_register_field_array(proto_iccp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_iccp = expert_register_protocol(proto_iccp);
    expert_register_field_array(expert_iccp, ei, array_length(ei));

    /* Preferences module (lets us register the DSD mapping UAT). */
    module_t *iccp_module = prefs_register_protocol(proto_iccp, NULL);
    uat_t *iccp_dsd_uat = uat_new(
        "ICCP DSD Mapping",
        sizeof(iccp_dsd_record_t),
        "iccp_dsd",                   /* config-file name in the user's profile */
        TRUE,                         /* user can edit */
        &iccp_dsd_records,
        &iccp_dsd_records_count,
        UAT_AFFECTS_DISSECTION,
        NULL,                         /* help URL */
        iccp_dsd_copy_cb,
        iccp_dsd_update_cb,
        iccp_dsd_free_cb,
        NULL,                         /* post_update_cb */
        NULL,                         /* reset_cb */
        iccp_dsd_fields);
    prefs_register_uat_preference(iccp_module, "dsd_mapping",
        "DSD (Data Set Definition) variable-name mapping",
        "Maps (domain, transfer set, slot) tuples to the operator's "
        "variable names so the recovered-points subtree can label each "
        "point. Useful when the capture started mid-session and the "
        "DefineNamedVariableList PDU that defined the data set was not "
        "captured. One row per slot. Slot is 0-based and matches "
        "iccp.point.slot.",
        iccp_dsd_uat);

    /* Per-point-name stats axes. Default OFF because the leaf count
     * scales with the union of all named slots across all Transfer Sets
     * (thousands in real-world Statkraft captures), which materially
     * slows the stats tree retap and the GUI render. Toggle requires
     * the user to close and reopen Statistics -> ICCP/Statistics: the
     * stats_tree init callback samples this preference once per dialog
     * open and conditionally creates the parent nodes. */
    prefs_register_bool_preference(iccp_module, "stats_per_point_name",
        "Per-point-name stats axes",
        "When enabled, the ICCP/Statistics tree adds two opt-in axes -- "
        "'Points by name (per Transfer Set)' (counts) and 'Point values "
        "by name (per Transfer Set)' (avg/min/max float) -- nested as "
        "TransferSet -> point name. Resolves names via the auto-discovered "
        "DSDs (DefineNamedVariableList frames in the capture) and the "
        "manual DSD Mapping above; unresolved slots are labelled 'slot N "
        "(unresolved)'. Default OFF -- expensive for Statkraft-scale "
        "captures. Close and reopen the stats dialog after toggling.",
        &iccp_pref_stats_per_point_name);

    /* Reset the auto-discovered DSD map between captures. Memory is
     * wmem_file_scope so Wireshark frees the contents on file close;
     * we just need to drop the dangling static pointer. */
    register_init_routine(iccp_dsd_auto_reset);

    iccp_handle = create_dissector_handle(dissect_iccp, proto_iccp);
    register_postdissector(iccp_handle);

    /* Expose a tap so external listeners (stats_tree, Lua, custom taps)
     * can consume per-packet ICCP attributes. */
    proto_iccp_tap = register_tap("iccp");

    /* Export Objects integration: File -> Export Objects -> ICCP shows
     * one row per DefineNamedVariableList-Request seen on the wire and
     * lets the user Save / Save All to CSV (slot,var_name). The
     * register_export_object call both registers the tap listener and
     * (on Wireshark 4.2 / 4.4 / 4.6) returns the tap id directly --
     * stash it for tap_queue_packet inside iccp_dsd_capture. */
    iccp_dsd_eo_tap = register_export_object(proto_iccp,
                                             eo_iccp_packet_cb,
                                             NULL /* reset_cb */);

    /* Register the built-in stats tree. Enables:
     *   tshark -z iccp,tree -r file.pcap
     * and the same node under Statistics -> ICCP in the GUI. */
    /* Third arg is the abbrev. Wireshark auto-appends ",tree" when
     * listing -z options, so passing "iccp" yields "iccp,tree" on the
     * command line. */
    /* TL_REQUIRES_PROTO_TREE forces Wireshark to RE-DISSECT each
     * packet on every stats retap (dialog open, Apply, Reload). Without
     * this, retap replays cached tap data without rebuilding the proto
     * tree -- our analysis runs at dissection time, so a replay sees
     * no fresh tap_queue calls and the conditional axes show empty
     * (only the unconditional ICCP-peers and PDU-sizes ones tick from
     * pinfo). With it, every retap re-runs the wrapper, MMS, and our
     * analysis, and stats populate identically every time. */
    stats_tree_register_plugin("iccp", "iccp", "ICCP/Statistics",
                               TL_REQUIRES_PROTO_TREE,
                               iccp_stats_tree_packet,
                               iccp_stats_tree_init,
                               NULL);
}

/* Always-on "frame" tap listener. Its sole purpose is to keep the
 * TL_REQUIRES_PROTO_TREE flag active so Wireshark builds the full
 * proto tree on every packet, every pass. The stats callback
 * (iccp_stats_tree_packet) is now self-sufficient -- it re-derives
 * all data from edt->tree -- so this listener no longer needs to
 * do any analysis or tap-queueing itself. */
static tap_packet_status
iccp_force_tree_packet(void *tapdata _U_, packet_info *pinfo _U_,
                       epan_dissect_t *edt _U_, const void *p _U_,
                       tap_flags_t flags _U_)
{
    return TAP_PACKET_DONT_REDRAW;
}

/* Auto-inject the canonical ICCP / TASE.2 PRES context binding.
 *
 * Real-world ICCP captures almost universally use Presentation Context
 * Identifier 3 mapped to MMS abstract syntax 1.0.9506.2.1, but that
 * mapping is normally negotiated in the A-ASSOCIATE (AARQ/AARE)
 * exchange at the start of an association. Captures that start
 * mid-session (the typical case for utility operators dropping a tap
 * on a long-lived link) miss the AARQ. Without the mapping, Wireshark
 * marks every DT SPDU as "dissector is not available", MMS never
 * dispatches, and our post-dissector never sees the data.
 *
 * The standard manual workaround is documented in the README's
 * "Using the plugin on a real-world ICCP capture" section: edit
 * Edit -> Preferences -> Protocols -> PRES -> Users Context List.
 * That step is fragile (every fresh user trips on it) and silently
 * makes the plugin look broken on perfectly-good captures.
 *
 * Instead we add the canonical ICCP binding to the in-memory
 * pres.users_table at plugin load time. If the user already has an
 * entry for PCI 3 with a different OID, our entry doesn't override
 * it -- pres looks up by ctx_id and returns the first match, and
 * our load happens at plugin handoff which is BEFORE the file
 * preferences are loaded back into the UAT. Net effect: when the
 * user has a custom binding, theirs wins; when they don't, our
 * canonical default kicks in and the capture just works.
 *
 * Idempotent via a static guard so re-handoff (triggered by pref
 * changes elsewhere) doesn't accumulate duplicate entries. */
static void
iccp_inject_pres_binding(void)
{
    static gboolean injected = FALSE;
    if (injected) return;
    injected = TRUE;

    uat_t *pres_uat = uat_get_table_by_name("PRES Users Context List");
    if (!pres_uat) return;

    /* pres_user_t layout from epan/dissectors/packet-pres.c (stable
     * across Wireshark 3.x / 4.x). uat_add_record invokes the table's
     * registered copy_cb (pres_copy_cb) which deep-copies the OID,
     * so our string literal pointer is fine -- PRES owns the copy. */
    typedef struct {
        unsigned  ctx_id;
        char     *oid;
    } iccp_pres_user_t;

    static const struct {
        unsigned    ctx_id;
        const char *oid;
        const char *label;
    } defaults[] = {
        { 3, "1.0.9506.2.1", "MMS / TASE.2 (canonical ICCP PCI)" },
    };
    for (size_t i = 0; i < sizeof defaults / sizeof defaults[0]; i++) {
        iccp_pres_user_t rec = {
            .ctx_id = defaults[i].ctx_id,
            .oid    = (char *)defaults[i].oid,
        };
        uat_add_record(pres_uat, &rec, TRUE);
    }
}

void
proto_reg_handoff_iccp(void)
{
    iccp_inject_pres_binding();

    /* Locate the MMS dissector. It's a built-in (not a plugin) so
     * find_dissector_add_dependency should always succeed; if it
     * doesn't, we fall back to post-dissector-only operation and the
     * user gets the old GUI behaviour.
     *
     * Use find_dissector_add_dependency rather than plain find_dissector
     * so Wireshark's tree optimizer registers proto_iccp as depending
     * on proto_mms. The optimizer uses these dependencies plus the
     * post-dissector wanted-hfids set to decide which MMS fields to
     * preserve in the proto tree on every dissection -- including the
     * stats retap path that's been silently dropping fields and
     * leaving our walker with nothing to find. The dependency has to
     * be registered to make the wanted-hfids actually persist. */
    mms_handle = find_dissector_add_dependency("mms", proto_iccp);
    if (mms_handle) {
        /* Register OUR handler at the canonical MMS abstract-syntax
         * OID. This OVERRIDES the MMS dissector's own registration
         * for the same OID (last-registered wins in the BER OID
         * dispatch table, and plugin handoffs run after built-in
         * dissector handoffs). PRES then calls us; we call MMS via
         * its handle and then run our analysis -- all during
         * dissection, fixing the GUI Protocol/Info columns and the
         * stats dialog timing problems documented in HANDOVER S4. */
        dissector_handle_t our_oid_handle =
            create_dissector_handle(iccp_dispatch_via_oid, proto_iccp);
        register_ber_oid_dissector_handle("1.0.9506.2.1", our_oid_handle,
                                          proto_iccp, "ICCP/TASE.2");
        /* Some IEC 61850-flavoured MMS uses a different abstract syntax
         * OID. Register under that one too so we wrap MMS regardless. */
        register_ber_oid_dissector_handle("1.0.9506.2.3", our_oid_handle,
                                          proto_iccp, "ICCP/TASE.2 (IEC 61850 syntax)");
    }


    /* Tell epan to keep these MMS fields alive in the proto tree so our
     * post-dissector can read them even when tshark is running without
     * -V. asn2wrs registers duplicate hf ids for CHOICE alternatives
     * that appear at multiple use sites (e.g. mms.read_element has one
     * hfid under ConfirmedServiceRequest and another under
     * ConfirmedServiceResponse). proto_registrar_get_id_byname() returns
     * only the first match; if we seed wanted-hfids from those cached
     * ids we miss the duplicate, and the tree optimizer elides it on
     * first-pass dissection. So walk the full registrar and add every
     * hfid whose abbrev matches one of our targets. O(N) once at load.
     * The API takes ownership of the GArray -- do not free it. */
    static const char *want_abbrevs[] = {
        "mms.confirmed_RequestPDU_element",
        "mms.confirmed_ResponsePDU_element",
        "mms.confirmed_ErrorPDU_element",
        "mms.initiate_RequestPDU_element",
        "mms.initiate_ResponsePDU_element",
        "mms.conclude_RequestPDU_element",
        "mms.conclude_ResponsePDU_element",
        "mms.rejectPDU_element",
        "mms.informationReport_element",
        "mms.read_element",
        "mms.write_element",
        "mms.getNameList_element",
        "mms.getVariableAccessAttributes_element",
        "mms.defineNamedVariableList_element",
        "mms.deleteNamedVariableList_element",
        "mms.Identifier",
        "mms.itemId",
        "mms.objectName_domain_specific_itemId",  /* 4.6 abbrev */
        "mms.vmd_specific",
        "mms.aa_specific",
        "mms.domainId",
        "mms.domainSpecific",
        "mms.newIdentifier",
        /* Data-payload accounting (for iccp.report.* summary fields). */
        "mms.AccessResult",
        "mms.failure",
        "mms.structure_element",
        "mms.structure",        /* 4.6 abbrev for the same wrapper */
        "mms.success_element",
        "mms.success",
        "mms.Data",
        "mms.data_element",
        "mms.floating_point",
        "mms.data_bit-string",
        "mms.data.binary-time",
        "mms.data.visible-string",
        "mms.data.octet-string",
        NULL
    };

    GArray *wanted = g_array_new(FALSE, FALSE, sizeof(int));
    int proto_mms = proto_get_id_by_filter_name("mms");
    if (proto_mms > 0) {
        void *cookie = NULL;
        for (header_field_info *h = proto_get_first_protocol_field(proto_mms, &cookie);
             h != NULL;
             h = proto_get_next_protocol_field(proto_mms, &cookie)) {
            if (!h->abbrev) continue;
            for (int j = 0; want_abbrevs[j]; j++) {
                if (strcmp(h->abbrev, want_abbrevs[j]) == 0) {
                    g_array_append_val(wanted, h->id);
                    break;
                }
            }
        }
    }
    set_postdissector_wanted_hfids(iccp_handle, wanted);

    /* Force a full proto tree on every packet, every pass.
     *
     * Without this, Wireshark's GUI does a "column-only" first pass
     * that tags each frame with its protocol but doesn't build the
     * full proto tree -- it only builds the tree on demand when the
     * user clicks a frame, or when a tap listener requires it. Our
     * post-dissector reads MMS field_info entries to derive iccp.*
     * items, so without a tree it has nothing to scrape, and the
     * file-wide `iccp` filter matches zero frames even though every
     * clicked-on packet shows the ICCP subtree fine.
     *
     * set_postdissector_wanted_hfids() above is supposed to handle
     * this, but in practice the GUI still skips the tree on
     * non-displayed frames. The bulletproof fix is to register an
     * always-on tap listener that requires PROTO_TREE -- its
     * presence makes Wireshark build the tree unconditionally for
     * every packet, every session, including on fresh file open
     * before the user touches anything. The "frame" tap fires once
     * per packet so it's the cheapest hook; the listener itself
     * does nothing. */
    GString *err = register_tap_listener("frame", NULL, NULL,
                                         TL_REQUIRES_PROTO_TREE,
                                         NULL, iccp_force_tree_packet,
                                         NULL, 0);
    if (err) {
        /* Tap "frame" should always be present in stock Wireshark;
         * if registration ever fails we silently fall back to the
         * wanted-hfids-only behaviour (works in tshark, partial in
         * GUI). */
        g_string_free(err, TRUE);
    }

}
