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
#include <epan/proto_data.h>
#include <epan/dissectors/packet-ber.h>

/* uat_add_record is exported from libwireshark but its prototype lives
 * in epan/uat-int.h which plugins should not depend on. Declare it
 * locally with the same signature. Stable across Wireshark 3.x/4.x. */
extern void *uat_add_record(uat_t *uat, const void *orig_rec_ptr, bool valid_rec);

/* Per-frame "already processed" flag key for p_add_proto_data. Used to
 * de-duplicate when a frame would otherwise hit both the OID-level
 * wrapper (during dissection) and the post-dissector (after dissection). */
#define ICCP_PFRAME_DONE_KEY 0xCAFEBABEu

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

/* TASE.2 IndicationPoint quality (per IEC 60870-6-503). Encoded as a
 * 1-byte BIT STRING in MMS:
 *   bits 7-6  validity         00=VALID  01=HELD  10=SUSPECT  11=NOT_VALID
 *   bit  5    normal           0=NORMAL  1=OFF_NORMAL
 *   bit  4    timestamp_qual   0=VALID   1=INVALID
 *   bits 3-2  current_source   00=CURRENT 01=HELD 10=SUBSTITUTED 11=GARBLED
 *   bits 1-0  reserved
 * Each subfield is exposed as its own filterable hf so users can
 * graph or filter individual flags; iccp.quality is the raw byte for
 * the bitmask child rendering, iccp.quality.summary is a one-line
 * human-friendly digest like "VALID/CURRENT/NORMAL/TS_OK". */
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
static int hf_iccp_point_summary     = -1;
static int hf_iccp_point_value       = -1;
static int hf_iccp_point_quality     = -1;
static int hf_iccp_point_index       = -1;

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

/* Tap payload: everything a listener (stats_tree, custom Lua tap, an
 * external analysis) might reasonably want to know about a single ICCP
 * packet. Allocated from pinfo->pool (the per-packet wmem scope), so
 * listeners must copy any pointer they need to retain. */
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

static const value_string iccp_q_source_vals[] = {
    { 0, "CURRENT" },
    { 1, "HELD" },
    { 2, "SUBSTITUTED" },
    { 3, "GARBLED" },
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
    const char *normal = (q & ICCP_Q_NORMAL_MASK)     ? "OFF_NORMAL" : "NORMAL";
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
        else if (!strcmp(s, "structure_element"))   flags->structure_count++;
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
              || !strcmp(s, "vmd_specific")
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

/* Per-walk context so we can number points and emit aggregate stats. */
typedef struct {
    guint32  point_index;        /* incremented as we synthesise iccp.point rows */
    /* Per-PDU point statistics, harvested by maybe_synthesise_point()
     * for the post-dissector to forward to the tap. */
    guint32  points_valid;
    guint32  points_held;
    guint32  points_suspect;
    guint32  points_notvalid;
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
} iccp_walk_ctx_t;

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
    proto_node *fp_node = NULL;
    proto_node *bs_node = NULL;
    int floats = 0, bitstrings = 0;
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
            const char *a = cfi->hfinfo->abbrev;
            if (strcmp(a, "mms.floating_point") == 0) {
                fp_node = cur; floats++;
            } else if (strcmp(a, "mms.data_bit-string") == 0) {
                bs_node = cur; bitstrings++;
            }
        }
        for (proto_node *cc = cur->first_child; cc; cc = cc->next) {
            stk_t *s = (stk_t *)g_alloca(sizeof(stk_t));
            s->p = cc; s->next = stack; stack = s;
        }
    }
    if (floats != 1 || bitstrings != 1 || !fp_node || !bs_node) return;

    field_info *fp_fi = PNODE_FINFO(fp_node);
    field_info *bs_fi = PNODE_FINFO(bs_node);
    if (!fp_fi || fp_fi->length < 5 || !fp_fi->ds_tvb) return;
    if (!bs_fi || bs_fi->length < 1 || !bs_fi->ds_tvb) return;
    if (tvb_get_guint8(fp_fi->ds_tvb, fp_fi->start) != 8) return;

    gfloat  v = tvb_get_ntohieee_float(fp_fi->ds_tvb, fp_fi->start + 1);
    guint8  q = tvb_get_guint8(bs_fi->ds_tvb, bs_fi->start);

    char qbuf[64];
    iccp_quality_summary(qbuf, sizeof qbuf, q);

    char line[160];
    g_snprintf(line, sizeof line, "Point #%u: %.6g  [%s]",
               ctx->point_index, v, qbuf);
    ctx->point_index++;

    /* Promote the structure_element to a subtree (it usually already
     * is one, but proto_item_add_subtree is idempotent for our
     * ett_iccp_point on a fresh node) and add the synthesis row. */
    proto_tree *sub = proto_item_add_subtree(node, ett_iccp_point);
    proto_item *pit = proto_tree_add_string(sub, hf_iccp_point_summary,
                                            fp_fi->ds_tvb,
                                            fp_fi->start,
                                            (bs_fi->start + bs_fi->length)
                                              - fp_fi->start,
                                            line);
    proto_item_set_generated(pit);
    proto_tree *psub = proto_item_add_subtree(pit, ett_iccp_point);
    proto_item *vi = proto_tree_add_float(psub, hf_iccp_point_value,
                                          fp_fi->ds_tvb, fp_fi->start,
                                          fp_fi->length, v);
    proto_item_set_generated(vi);
    proto_item *qi = proto_tree_add_string(psub, hf_iccp_point_quality,
                                           bs_fi->ds_tvb, bs_fi->start,
                                           bs_fi->length, qbuf);
    proto_item_set_generated(qi);
    proto_item *ii = proto_tree_add_uint(psub, hf_iccp_point_index,
                                         fp_fi->ds_tvb, fp_fi->start, 0,
                                         ctx->point_index - 1);
    proto_item_set_generated(ii);

    /* Roll the synthesised point into the per-PDU aggregates so the
     * post-dissector can forward them to the tap (Tier 3 stats). */
    guint8 vc = (guint8)((q & ICCP_Q_VALIDITY_MASK) >> 6);
    switch (vc) {
        case 0: ctx->points_valid++;    break;
        case 1: ctx->points_held++;     break;
        case 2: ctx->points_suspect++;  break;
        case 3: ctx->points_notvalid++; break;
    }
    if (!ctx->has_value || v < ctx->v_min) ctx->v_min = v;
    if (!ctx->has_value || v > ctx->v_max) ctx->v_max = v;
    ctx->v_sum    += v;
    ctx->has_value = TRUE;

    /* Per-point detail for STAT_DT_FLOAT stats axes. Allocated upstream
     * from pinfo->pool; the listener iterates these in lock-step so a
     * mismatch between the two arrays would silently drop validity
     * information (kept consistent here by appending both unconditionally). */
    if (ctx->point_values) {
        wmem_array_append_one(ctx->point_values, v);
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
    proto_item *it = proto_tree_add_float(sub, hf_iccp_value_real,
                                          fi->ds_tvb, fi->start,
                                          fi->length, val);
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

    maybe_decode_float(node);
    maybe_decode_quality(node);
    if (ctx) maybe_synthesise_point(node, ctx);

    proto_tree_children_foreach(node, attach_decoded_values, ctx);
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
    if (mms_handle) {
        consumed = call_dissector_only(mms_handle, tvb, pinfo, tree, data);
    }
    if (consumed <= 0) {
        consumed = tvb_captured_length(tvb);
    }

    /* Run the existing analysis. dissect_iccp checks the de-dup flag
     * at entry so we mark the frame BEFORE calling it -- otherwise
     * the post-dissector pass would have to re-run the same analysis
     * later for nothing. Wait, we want analysis to run NOW from the
     * wrapper. The flag is set *after* analysis to mean "post-dissector
     * skip me". */
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

    iccp_pdu_flags_t flags;
    iccp_name_scan_t scan;
    walk_tree(pinfo, tree, &flags, &scan);

    /* Attach inline decoded values for any MMS leaf we can interpret:
     *  - floating_point bytes -> real number under the leaf
     *  - 1-byte bit-string    -> TASE.2 quality flags decoded
     *  - (float, bit-string) sibling pair inside a structure ->
     *    synthesised "Point #N: <value> [quality]" row at the
     *    structure level, so a 250-point InformationReport reads
     *    as 250 named lines.
     * Done unconditionally on every MMS-bearing packet, so this
     * works on heavily anonymized captures too. */
    iccp_walk_ctx_t walk_ctx = { 0 };
    /* Per-point arrays live in wmem_file_scope (not pinfo->pool) so the
     * tap_info that references them survives Wireshark stats-listener
     * replay across retaps and dialog re-opens. See the tap_info
     * allocation comment for the full rationale. */
    walk_ctx.point_values     = wmem_array_new(wmem_file_scope(), sizeof(gfloat));
    walk_ctx.point_validities = wmem_array_new(wmem_file_scope(), sizeof(guint8));
    if (flags.floating_point_count > 0
        || flags.bit_string_count   > 0
        || flags.structure_count    > 0) {
        proto_tree_children_foreach(tree, attach_decoded_values, &walk_ctx);
    }

    iccp_op_t op = classify_operation(&flags);

    iccp_conv_t *info = iccp_conv_get(pinfo, TRUE);
    if (!info)
        return 0;

    /* Association tracking. */
    if (op == ICCP_OP_ASSOC_REQ || op == ICCP_OP_ASSOC_RESP) {
        if (info->state == ICCP_ASSOC_NONE) {
            info->state = ICCP_ASSOC_CANDIDATE;
            info->initiate_frame = pinfo->num;
        }
    }

    if (scan.matched && info->state != ICCP_ASSOC_CONFIRMED) {
        info->state = ICCP_ASSOC_CONFIRMED;
        info->confirmed_frame = pinfo->num;
        g_strlcpy(info->confirmation_name, scan.matched_name,
                  sizeof info->confirmation_name);
        info->confirmation_cb = scan.matched->cb;
    }

    /* Device Control state machine (Block 5). */
    iccp_device_entry_t *dev     = NULL;
    const char          *dev_sub = NULL;
    gboolean             dev_bad_operate = FALSE;
    gboolean             dev_stale_select = FALSE;
    if (scan.matched && scan.matched->cb == 5 && scan.matched_name) {
        dev_sub = iccp_device_subop(scan.matched_name);
        if (dev_sub) {
            char base[64];
            iccp_device_base_name(scan.matched_name, base, sizeof base);
            /* Cross-conversation lookup: Select on conversation A will
             * correlate with Operate on conversation B if they target
             * the same (server_addr, server_port, device_base). */
            dev = iccp_device_lookup(pinfo, base, TRUE);
            if (dev) {
                conversation_t *conv = find_conversation_pinfo(pinfo, 0);
                guint32 conv_idx = conv ? conv->conv_index : 0;
                if (strcmp(dev_sub, "Select") == 0) {
                    dev->state             = ICCP_DEV_SELECTED;
                    dev->select_frame      = pinfo->num;
                    dev->select_conv_index = conv_idx;
                } else if (strcmp(dev_sub, "SBO-Operate") == 0) {
                    if (dev->state != ICCP_DEV_SELECTED)
                        dev_bad_operate = TRUE;
                    else if (pinfo->num - dev->select_frame > 10000) /* rough */
                        dev_stale_select = TRUE;
                    dev->state = ICCP_DEV_OPERATED;
                } else if (strcmp(dev_sub, "Cancel") == 0) {
                    dev->state = ICCP_DEV_IDLE;
                }
            }
        }
    }

    /* Decide whether this packet is worth surfacing as ICCP. We
     * surface unconditionally on InformationReport / Read-Response
     * because those carry typed-data values (floats, bit-strings,
     * timestamps) we want to decode -- this works even on
     * heavily-anonymized captures where the variable names have
     * been hashed and our TASE.2 name-match heuristic cannot run.
     * For plain IEC 61850 MMS the iccp.* fields will be sparse but
     * the decoded float values are still useful. */
    gboolean surface =
        info->state == ICCP_ASSOC_CONFIRMED
        || op == ICCP_OP_ASSOC_REQ
        || op == ICCP_OP_ASSOC_RESP
        || op == ICCP_OP_CONCLUDE_REQ
        || op == ICCP_OP_CONCLUDE_RESP
        || op == ICCP_OP_INFORMATION_REPORT
        || op == ICCP_OP_READ_RESP
        || op == ICCP_OP_WRITE_RESP
        || scan.matched != NULL;

    if (!surface)
        return 0;

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
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, TRUE);
    col_set_writable(pinfo->cinfo, COL_INFO,     TRUE);
    col_clear_fence(pinfo->cinfo, COL_PROTOCOL);
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICCP");

    /* Info column: <Op> on <Object>: <Name> */
    {
        const char *op_str = iccp_op_str(op);
        if (op_str && scan.matched) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ",
                                "ICCP %s [%s: %s]",
                                op_str, scan.matched->category, scan.matched_name);
        } else if (op_str) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ",
                                "ICCP %s", op_str);
        } else if (scan.matched) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ",
                                "ICCP %s: %s",
                                scan.matched->category, scan.matched_name);
        } else {
            col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", "ICCP");
        }
    }

    /* Proto tree. */
    proto_item *ti    = proto_tree_add_item(tree, proto_iccp, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(ti);
    proto_tree *itree = proto_item_add_subtree(ti, ett_iccp);


    const char *state_str =
        info->state == ICCP_ASSOC_CONFIRMED ? "Confirmed ICCP" :
        info->state == ICCP_ASSOC_CANDIDATE ? "Candidate (Initiate seen)" :
        "Unknown";
    proto_item *state_it = proto_tree_add_string(itree, hf_iccp_association_state,
                                                 tvb, 0, 0, state_str);
    proto_item_set_generated(state_it);

    /* Prefer this PDU's actual variable name. scan.matched_name is set
     * only when the name matched a TASE.2 reserved-name pattern;
     * scan.first_name is the first identifier the tree walk saw on this
     * PDU regardless of pattern match. info->confirmation_name is the
     * (often stale) name that originally promoted the association --
     * useful as a last resort but it doesn't reflect what this frame is
     * actually accessing. */
    const char *display_name =
        scan.matched_name           ? scan.matched_name :
        scan.first_name             ? scan.first_name   :
        info->confirmation_name[0]  ? info->confirmation_name :
                                      NULL;
    if (display_name) {
        proto_item *nit = proto_tree_add_string(itree, hf_iccp_object_name,
                                                tvb, 0, 0, display_name);
        proto_item_set_generated(nit);
    }

    const char *op_str = iccp_op_str(op);
    if (op_str) {
        proto_item *oit = proto_tree_add_string(itree, hf_iccp_operation,
                                                tvb, 0, 0, op_str);
        proto_item_set_generated(oit);
    }

    if (scan.matched) {
        proto_item *cit = proto_tree_add_string(itree, hf_iccp_object_category,
                                                tvb, 0, 0, scan.matched->category);
        proto_item_set_generated(cit);
        proto_item *cb_it = proto_tree_add_uint(itree, hf_iccp_conformance_block,
                                                tvb, 0, 0, scan.matched->cb);
        proto_item_set_generated(cb_it);
        expert_add_info(pinfo, cit, &ei_iccp_object_seen);
    }

    /* Surface name scope (VCC vs Bilateral) regardless of whether
     * we recognised the name pattern -- the scope is independent of
     * pattern classification. */
    {
        const char *sc = iccp_scope_str(scan.scope);
        if (sc) {
            proto_item *sit = proto_tree_add_string(itree, hf_iccp_scope,
                                                    tvb, 0, 0, sc);
            proto_item_set_generated(sit);
        }
        if (scan.scope == ICCP_SCOPE_BILATERAL && scan.domain_id) {
            proto_item *dit = proto_tree_add_string(itree, hf_iccp_domain,
                                                    tvb, 0, 0, scan.domain_id);
            proto_item_set_generated(dit);
        }
    }

    if (op == ICCP_OP_ASSOC_REQ || op == ICCP_OP_ASSOC_RESP) {
        expert_add_info(pinfo, ti, &ei_iccp_association_seen);
    }
    if (op == ICCP_OP_INFORMATION_REPORT) {
        expert_add_info(pinfo, ti, &ei_iccp_info_report);
    }

    /* Report / typed-data summary. We don't re-parse the BER -- the MMS
     * dissector already did that -- but we surface the counts MMS
     * emitted so users can e.g. filter for
     *   iccp.report.point_count > 50
     * or spot a partially-failed report via iccp.report.failure_count.
     * Applied on any PDU that carries MMS AccessResults (i.e. a
     * Read-Response or an InformationReport), on a confirmed ICCP
     * conversation. */
    if (flags.access_result_count > 0
        && (op == ICCP_OP_INFORMATION_REPORT
         || op == ICCP_OP_READ_RESP
         || op == ICCP_OP_WRITE_RESP)) {
        proto_item *pit = proto_tree_add_uint(itree, hf_iccp_report_points,
                                              tvb, 0, 0, flags.access_result_count);
        proto_item_set_generated(pit);
        guint32 succ = (flags.failure_count <= flags.access_result_count)
                     ? (flags.access_result_count - flags.failure_count) : 0;
        proto_item *sit = proto_tree_add_uint(itree, hf_iccp_report_success,
                                              tvb, 0, 0, succ);
        proto_item_set_generated(sit);
        proto_item *fit = proto_tree_add_uint(itree, hf_iccp_report_failure,
                                              tvb, 0, 0, flags.failure_count);
        proto_item_set_generated(fit);
        /* A TASE.2 DSConditions point is always a structure of several
         * primitives (at minimum: value + quality + timestamp). Treat
         * the presence of at least one structure as strong evidence. */
        gboolean structured = (flags.structure_count > 0);
        proto_item *bit = proto_tree_add_boolean(itree, hf_iccp_report_structured,
                                                 tvb, 0, 0, structured);
        proto_item_set_generated(bit);

        char summary[160];
        g_snprintf(summary, sizeof summary,
                   "floats=%u bit-strings=%u binary-times=%u visible-strings=%u octet-strings=%u",
                   flags.floating_point_count,
                   flags.bit_string_count,
                   flags.binary_time_count,
                   flags.visible_string_count,
                   flags.octet_string_count);
        proto_item *sumit = proto_tree_add_string(itree, hf_iccp_report_summary,
                                                  tvb, 0, 0, summary);
        proto_item_set_generated(sumit);
    }

    /* Device sub-tree. */
    if (dev) {
        proto_item *dti = proto_tree_add_string(itree, hf_iccp_device_state,
                                                tvb, 0, 0,
                                                dev->state == ICCP_DEV_SELECTED ? "Selected" :
                                                dev->state == ICCP_DEV_OPERATED ? "Operated" :
                                                "Idle");
        proto_item_set_generated(dti);
        proto_tree *dsub = proto_item_add_subtree(dti, ett_iccp_device);

        if (dev_sub) {
            char note[128];
            g_snprintf(note, sizeof note, "Device sub-operation: %s on %s",
                       dev_sub, dev->name);
            proto_item *nit = proto_tree_add_string(dsub, hf_iccp_note,
                                                    tvb, 0, 0, note);
            proto_item_set_generated(nit);
        }

        if (dev_bad_operate) {
            expert_add_info(pinfo, dti, &ei_iccp_device_no_select);
        } else if (dev_stale_select) {
            expert_add_info(pinfo, dti, &ei_iccp_device_stale_sel);
        } else if (strcmp(dev_sub ? dev_sub : "", "SBO-Operate") == 0
                || strcmp(dev_sub ? dev_sub : "", "Direct-Operate") == 0) {
            expert_add_info(pinfo, dti, &ei_iccp_device_operate);
        }
    }

    /* Queue tap_info for any listener (stats_tree, custom tap, Lua tap)
     * interested in ICCP packet attributes. Packet-scope allocation:
     * listeners must copy anything they want to keep. */
    if (have_tap_listener(proto_iccp_tap)) {
        /* Allocate the tap-info struct in wmem_file_scope rather than
         * pinfo->pool. Wireshark's GUI stats listener replays cached
         * tap data on retap and on dialog re-open without re-running
         * dissection in some flows; pinfo->pool is freed at end of
         * each packet's dissection, so tap_info structs allocated
         * there end up dangling -- the unconditional axes (ICCP peers,
         * PDU sizes, which read from pinfo) still fire but every
         * conditional axis (Operation, Object category, Conformance
         * Block, ...) reads NULL/zero from the dangling memory and
         * silently drops the tick. wmem_file_scope persists for the
         * file's lifetime so replays always see live data. */
        iccp_tap_info_t *ti2 = wmem_new0(wmem_file_scope(), iccp_tap_info_t);
        ti2->op              = (int)op;
        ti2->op_str          = iccp_op_str(op);                /* string literal */
        ti2->assoc_state     = (int)info->state;
        if (scan.matched) {
            ti2->cb              = scan.matched->cb;
            ti2->object_category = scan.matched->category;     /* static patterns table */
            /* scan.matched_name points into MMS dissector's pinfo->pool;
             * dup into file_scope for replay safety. */
            ti2->object_name     = scan.matched_name
                                 ? wmem_strdup(wmem_file_scope(), scan.matched_name)
                                 : NULL;
        }
        if (dev) {
            ti2->device_name  = dev->name;                     /* already wmem_file_scope */
            ti2->device_state = (int)dev->state;
            ti2->device_sub   = dev_sub;                       /* string literal */
        }
        if (flags.access_result_count > 0
            && (op == ICCP_OP_INFORMATION_REPORT
             || op == ICCP_OP_READ_RESP
             || op == ICCP_OP_WRITE_RESP)) {
            ti2->report_points     = flags.access_result_count;
            ti2->report_failure    = flags.failure_count;
            ti2->report_success    = (flags.failure_count <= flags.access_result_count)
                                   ? (flags.access_result_count - flags.failure_count) : 0;
            ti2->report_structured = (flags.structure_count > 0);
        }

        /* Tier 3: forward per-point aggregates harvested by the
         * synthesis walker. set_name comes from the same name scan
         * that drives column/category labelling -- on captures with
         * intact ICCP names that's the Transfer-Set / variable list;
         * on heavily anonymised captures it's NULL and the tap
         * listener buckets under "(unnamed)". */
        /* Prefer this PDU's matched name; if no TASE.2 reserved pattern
         * matched, fall back to the first variable identifier seen on
         * the wire. Without this fallback, every EXAMPLE_UTIL_A-internal
         * (or other vendor-specific) name buckets under "(unnamed)"
         * in the per-set stats tree. */
        /* set_name and domain_id come from MMS pinfo->pool; dup into
         * file_scope for replay safety (see ti2 allocation comment). */
        {
            const char *raw_set = scan.matched_name ? scan.matched_name : scan.first_name;
            ti2->set_name = raw_set ? wmem_strdup(wmem_file_scope(), raw_set) : NULL;
        }
        ti2->scope           = iccp_scope_str(scan.scope);     /* string literal */
        ti2->domain_id       = scan.domain_id
                             ? wmem_strdup(wmem_file_scope(), scan.domain_id)
                             : NULL;
        ti2->point_count     = walk_ctx.point_index;
        ti2->points_valid    = walk_ctx.points_valid;
        ti2->points_held     = walk_ctx.points_held;
        ti2->points_suspect  = walk_ctx.points_suspect;
        ti2->points_notvalid = walk_ctx.points_notvalid;
        ti2->point_value_min = walk_ctx.v_min;
        ti2->point_value_max = walk_ctx.v_max;
        ti2->point_value_sum = walk_ctx.v_sum;
        ti2->has_point_values = walk_ctx.has_value;
        /* Per-point arrays for STAT_DT_FLOAT axes. Live for the
         * duration of pinfo->pool, which lasts past tap_queue_packet
         * into the listener invocations. */
        ti2->point_values_arr     = walk_ctx.point_values;
        ti2->point_validities_arr = walk_ctx.point_validities;

        tap_queue_packet(proto_iccp_tap, pinfo, ti2);
    }

    /* Return captured length, not 0. A post-dissector that returns 0
     * is treated as "didn't claim this packet" -- Wireshark then
     * skips adding "iccp" to pinfo->layers, and the Protocol column
     * is rendered from the layer chain's last entry ("mms"),
     * silently overriding our col_set_str(COL_PROTOCOL,"ICCP"). The
     * symptom in the GUI: every fix to columns and tap_listener
     * flags appears to do nothing. Returning a non-zero value adds
     * us to the chain so the column renders correctly. */
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
}

static tap_packet_status
iccp_stats_tree_packet(stats_tree *st,
                       packet_info *pinfo,
                       epan_dissect_t *edt _U_,
                       const void *p,
                       tap_flags_t flags _U_)
{
    const iccp_tap_info_t *ti = (const iccp_tap_info_t *)p;
    if (!ti) return TAP_PACKET_DONT_REDRAW;

    if (ti->op_str && *ti->op_str) {
        tick_stat_node(st, "Operation",          0, TRUE);
        tick_stat_node(st, ti->op_str, st_node_ops, FALSE);
    }
    if (ti->object_category && *ti->object_category) {
        tick_stat_node(st, "Object category",    0, TRUE);
        tick_stat_node(st, ti->object_category, st_node_categories, FALSE);
    }
    if (ti->cb > 0) {
        char cb_label[16];
        g_snprintf(cb_label, sizeof cb_label, "Block %u", ti->cb);
        tick_stat_node(st, "Conformance Block",  0, TRUE);
        tick_stat_node(st, cb_label, st_node_blocks, FALSE);
    }
    {
        const char *assoc =
            ti->assoc_state == ICCP_ASSOC_CONFIRMED ? "Confirmed ICCP" :
            ti->assoc_state == ICCP_ASSOC_CANDIDATE ? "Candidate"      :
            "Unknown";
        tick_stat_node(st, "Association state",  0, TRUE);
        tick_stat_node(st, assoc, st_node_assocs, FALSE);
    }
    if (ti->device_sub && *ti->device_sub) {
        tick_stat_node(st, "Device sub-operation", 0, TRUE);
        tick_stat_node(st, ti->device_sub, st_node_devices, FALSE);
    }
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

    /* Tier 3: per-Transfer-Set, quality, and value-range buckets.
     * Each iccp.point synthesised in this PDU contributes N to the set
     * and N to its validity class. The parent must accumulate the same
     * total (not just one tick per PDU) or Wireshark renders nonsense
     * percentages -- a 28-point PDU with the parent ticked once and
     * the child ticked 28 times produces "2800%" in the GUI. */
    if (ti->point_count > 0) {
        const char *set = (ti->set_name && *ti->set_name) ? ti->set_name : "(unnamed)";
        increase_stat_node(st, "Points per Transfer Set", 0, TRUE,  ti->point_count);
        increase_stat_node(st, set,             st_node_points_set, FALSE, ti->point_count);

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

        if (ti->has_point_values) {
            /* Coarse value-range buckets useful for sanity-checking a
             * grid capture at a glance (frequency vs MW vs setpoint
             * scale). The same data is in iccp.point.value for
             * fine-grained graphing via I/O Graph. */
            tick_stat_node(st, "Point value range", 0, TRUE);
            const char *bucket;
            if      (ti->point_value_max < 0)        bucket = "negative";
            else if (ti->point_value_max < 1)        bucket = "0..1 (per-unit)";
            else if (ti->point_value_max < 60)       bucket = "1..60 (Hz / pct)";
            else if (ti->point_value_max < 1000)     bucket = "60..1000";
            else if (ti->point_value_max < 100000)   bucket = "1k..100k";
            else                                     bucket = ">=100k";
            tick_stat_node(st, bucket, st_node_points_range, FALSE);
        }
    }

    /* Tier 5: per-peer pivot. address_to_str allocates from NULL pool
     * (heap), tick_stat_node copies the key, free immediately. */
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

    /* Name scope: VCC vs Bilateral. Bilateral PDUs typically carry
     * the high-value reads/writes; the per-domain pivot under
     * "Bilateral" lets you see at a glance which Bilateral Tables
     * are seeing the most traffic. */
    if (ti->scope) {
        tick_stat_node(st, "Operations by scope", 0, TRUE);
        tick_stat_node(st, ti->scope, st_node_scope, FALSE);
    }

    /* -- Tier 4: STAT_DT_FLOAT axes (Average / Min Val / Max Val). -- */

    /* Per-point value distributions. avg_stat_node_add_value_float
     * accumulates count + sum + min + max in the named node; calling
     * it on the parent ("by validity" / "by Transfer Set" / "by
     * Conformance Block") gives the cumulative distribution across
     * children, calling it on the child gives the per-bucket
     * distribution. The "Point values" leaf has no children -- it's
     * the global per-point distribution. */
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

                /* Global per-point value distribution. */
                avg_stat_node_add_value_float(st, "Point values (all numeric points)", 0, FALSE, v);

                /* By validity class -- parent + child. */
                avg_stat_node_add_value_float(st, "Point values by validity", 0,                    TRUE,  v);
                avg_stat_node_add_value_float(st, vname,                      st_node_pvalues_qual, FALSE, v);

                /* By Transfer Set name. */
                avg_stat_node_add_value_float(st, "Point values by Transfer Set", 0,                   TRUE,  v);
                avg_stat_node_add_value_float(st, set,                            st_node_pvalues_set, FALSE, v);

                /* By Conformance Block. */
                avg_stat_node_add_value_float(st, "Point values by Conformance Block", 0,                  TRUE,  v);
                avg_stat_node_add_value_float(st, cb_label,                            st_node_pvalues_cb, FALSE, v);
            }
        }
    }

    /* Per-PDU shape distributions. Only meaningful for PDUs that
     * actually carry AccessResults (InformationReport / Read-Response
     * / Write-Response). */
    if (ti->report_points > 0) {
        avg_stat_node_add_value_float(st, "Points per PDU", 0, FALSE, (gfloat)ti->point_count);

        const gfloat ratio = (gfloat)ti->report_success / (gfloat)ti->report_points;
        avg_stat_node_add_value_float(st, "Report success ratio per PDU", 0, FALSE, ratio);
    }

    /* Per-PDU quality mix as percentages. Same parent for all four so
     * the dialog shows a stacked picture of how the per-class mix
     * varies PDU to PDU (look at Average for the typical mix and
     * Max Val to spot worst-case SUSPECT bursts). */
    if (ti->point_count > 0) {
        const gfloat total = (gfloat)ti->point_count;
        avg_stat_node_add_value_float(st, "Quality mix per PDU (%)", 0,                  TRUE,  100.0f);
        avg_stat_node_add_value_float(st, "VALID%",     st_node_quality_mix, FALSE, 100.0f * (gfloat)ti->points_valid    / total);
        avg_stat_node_add_value_float(st, "HELD%",      st_node_quality_mix, FALSE, 100.0f * (gfloat)ti->points_held     / total);
        avg_stat_node_add_value_float(st, "SUSPECT%",   st_node_quality_mix, FALSE, 100.0f * (gfloat)ti->points_suspect  / total);
        avg_stat_node_add_value_float(st, "NOT_VALID%", st_node_quality_mix, FALSE, 100.0f * (gfloat)ti->points_notvalid / total);
    }

    /* PDU sizes, with per-Operation breakdown. Useful for capacity
     * planning ("how big is a typical InformationReport?") and for
     * spotting outliers ("a 4 KB Read-Request is suspicious"). */
    {
        const gfloat sz = (gfloat)pinfo->fd->pkt_len;
        avg_stat_node_add_value_float(st, "PDU sizes (bytes)", 0, TRUE, sz);
        if (ti->op_str && *ti->op_str)
            avg_stat_node_add_value_float(st, ti->op_str, st_node_pdu_sizes, FALSE, sz);
    }

    return TAP_PACKET_REDRAW;
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
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            "MMS floating-point primitive decoded to IEEE 754 single-"
            "precision. The MMS dissector shows these as raw bytes "
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
          { "Off-normal", "iccp.quality.off_normal",
            FT_BOOLEAN, 8, NULL, ICCP_Q_NORMAL_MASK,
            "0 = NORMAL, 1 = OFF_NORMAL. The point reading falls "
            "outside its declared normal range.",
            HFILL }
        },
        { &hf_iccp_quality_ts_invalid,
          { "Timestamp invalid", "iccp.quality.timestamp_invalid",
            FT_BOOLEAN, 8, NULL, ICCP_Q_TS_INVALID_MASK,
            "1 = the timestamp on this point cannot be trusted.",
            HFILL }
        },
        { &hf_iccp_quality_source,
          { "Source", "iccp.quality.source",
            FT_UINT8, BASE_DEC, VALS(iccp_q_source_vals), ICCP_Q_SOURCE_MASK,
            NULL, HFILL }
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
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            "Decoded numeric value of the point.",
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
            "Position of this point in the InformationReport "
            "(0-based, in tree-walk order).",
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

    iccp_handle = create_dissector_handle(dissect_iccp, proto_iccp);
    register_postdissector(iccp_handle);

    /* Expose a tap so external listeners (stats_tree, Lua, custom taps)
     * can consume per-packet ICCP attributes. */
    proto_iccp_tap = register_tap("iccp");

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

/* No-op tap callback: just exists to carry TL_REQUIRES_PROTO_TREE. */
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
     * find_dissector should always succeed; if it doesn't, we fall
     * back to post-dissector-only operation and the user gets the
     * old GUI behaviour. */
    mms_handle = find_dissector("mms");
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
        "mms.vmd_specific",
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
