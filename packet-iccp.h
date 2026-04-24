/* packet-iccp.h
 *
 * Wireshark ICCP / TASE.2 dissector plugin
 * IEC 60870-6 Inter-Control Center Communications Protocol
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ICCP_H
#define PACKET_ICCP_H

void proto_register_iccp(void);
void proto_reg_handoff_iccp(void);

#endif
