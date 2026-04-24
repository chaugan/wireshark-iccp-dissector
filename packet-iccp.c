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

#include <string.h>

#include "packet-iccp.h"

/* -------------------------------------------------------------------------
 * Registration state
 * ---------------------------------------------------------------------- */

static int proto_iccp = -1;

static int hf_iccp_association_state = -1;
static int hf_iccp_object_category   = -1;
static int hf_iccp_object_name       = -1;
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

static gint ett_iccp         = -1;
static gint ett_iccp_objects = -1;
static gint ett_iccp_device  = -1;

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

typedef struct {
    const iccp_name_pattern_t *matched;
    const char                *matched_name;
    const char                *first_name;
    guint                      total;
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
walk_tree(proto_tree *tree, iccp_pdu_flags_t *flags, iccp_name_scan_t *scan)
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
        else if (!strcmp(s, "Identifier")
              || !strcmp(s, "itemId")
              || !strcmp(s, "vmd_specific")
              || !strcmp(s, "domainId")
              || !strcmp(s, "domainSpecific")
              || !strcmp(s, "newIdentifier")) {
            if (fi->value) {
                const char *sv = fvalue_get_string(fi->value);
                iccp_consider_name(scan, sv);
            }
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

static int
dissect_iccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (!proto_is_frame_protocol(pinfo->layers, "mms"))
        return 0;
    if (!tree)
        return 0;

    iccp_pdu_flags_t flags;
    iccp_name_scan_t scan;
    walk_tree(tree, &flags, &scan);

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

    /* Decide whether this packet is worth surfacing as ICCP. */
    gboolean surface =
        info->state == ICCP_ASSOC_CONFIRMED
        || op == ICCP_OP_ASSOC_REQ
        || op == ICCP_OP_ASSOC_RESP
        || op == ICCP_OP_CONCLUDE_REQ
        || op == ICCP_OP_CONCLUDE_RESP
        || scan.matched != NULL;

    if (!surface)
        return 0;

    /* Protocol column. */
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

    if (info->confirmation_name[0]) {
        proto_item *nit = proto_tree_add_string(itree, hf_iccp_object_name,
                                                tvb, 0, 0, info->confirmation_name);
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
        iccp_tap_info_t *ti2 = wmem_new0(pinfo->pool, iccp_tap_info_t);
        ti2->op              = (int)op;
        ti2->op_str          = iccp_op_str(op);
        ti2->assoc_state     = (int)info->state;
        if (scan.matched) {
            ti2->cb              = scan.matched->cb;
            ti2->object_category = scan.matched->category;
            ti2->object_name     = scan.matched_name;
        }
        if (dev) {
            ti2->device_name  = dev->name;
            ti2->device_state = (int)dev->state;
            ti2->device_sub   = dev_sub;
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
        tap_queue_packet(proto_iccp_tap, pinfo, ti2);
    }

    return 0;
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
}

static tap_packet_status
iccp_stats_tree_packet(stats_tree *st,
                       packet_info *pinfo _U_,
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
    };

    static gint *ett[] = {
        &ett_iccp,
        &ett_iccp_objects,
        &ett_iccp_device,
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
    stats_tree_register_plugin("iccp", "iccp", "ICCP/Statistics",
                               0,
                               iccp_stats_tree_packet,
                               iccp_stats_tree_init,
                               NULL);
}

void
proto_reg_handoff_iccp(void)
{
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
}
