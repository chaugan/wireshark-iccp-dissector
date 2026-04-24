/* plugin.c
 *
 * Wireshark ICCP / TASE.2 dissector plugin
 * IEC 60870-6 Inter-Control Center Communications Protocol
 *
 * Plugin entry point — version metadata and plugin_register().
 * The dissector proper lives in packet-iccp.c.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_BUILD_DLL
#include <wireshark.h>
#include <epan/packet.h>
#include <epan/proto.h>

#if defined(__has_include)
#  if __has_include(<wsutil/plugins.h>)
#    include <wsutil/plugins.h>
#    define ICCP_HAVE_PLUGIN_DESCRIBE 1
#  endif
#endif

#include "packet-iccp.h"

#ifndef VERSION
#define VERSION "0.0.0"
#endif

WS_DLL_PUBLIC_DEF const char plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
#ifdef ICCP_HAVE_PLUGIN_DESCRIBE
WS_DLL_PUBLIC uint32_t plugin_describe(void);
#endif

void
plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_iccp;
    plug.register_handoff   = proto_reg_handoff_iccp;
    proto_register_plugin(&plug);
}

#ifdef ICCP_HAVE_PLUGIN_DESCRIBE
uint32_t
plugin_describe(void)
{
    return WS_PLUGIN_DESC_DISSECTOR;
}
#endif
