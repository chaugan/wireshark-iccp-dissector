#!/usr/bin/env bash
# Generate an ICCP-flavored PCAP for Phase 1 verification.
#
# Strategy: run libIEC61850's plain MMS server on a loopback port, then
# have mms_utility request variables with TASE.2-reserved names
# (Bilateral_Table_ID, TASE2_Version, DSConditions_..., Device_..., etc.).
# Every client request PDU carries the variable name as an MMS
# `Identifier` string on the wire -- which is exactly what our Phase 1
# post-dissector pattern-matches.
#
# The server will reply "object does not exist" for every request; we do
# not care about the reply semantics, only about the request bytes.

set -euo pipefail

PORT=10102
BIN=$HOME/src/libiec61850/build/examples
SERVER=$BIN/server_example_basic_io/server_example_basic_io
CLIENT=$BIN/mms_utility/mms_utility
OUTDIR=/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp/pcaps/generated
PCAP=$OUTDIR/iccp-phase1.pcap

mkdir -p "$OUTDIR"
rm -f "$PCAP"

# Kill any leftover server on our port.
fuser -k "$PORT/tcp" 2>/dev/null || true
sleep 0.3

echo "== start server on 127.0.0.1:$PORT =="
"$SERVER" "$PORT" >/tmp/iccp-server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# Wait until the server is accepting connections.
for i in $(seq 1 30); do
    if (echo >/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
        break
    fi
    sleep 0.1
done

echo "== start dumpcap on lo =="
sudo dumpcap -q -i lo -f "tcp port $PORT" -w "$PCAP" -a duration:30 >/tmp/iccp-dumpcap.log 2>&1 &
DUMP_PID=$!
# Wait briefly for dumpcap to open the pcap file.
sleep 0.7

echo "== run client requests =="
# Each -i/-r/-d invocation is its own MMS association: Initiate,
# one operation, Conclude. We intentionally span several ICCP-name
# categories so Phase 1 pattern-matching has breadth.
run_client() {
    local label=$1; shift
    echo "   [$label] mms_utility $*"
    "$CLIENT" -h 127.0.0.1 -p "$PORT" "$@" >/tmp/iccp-client.log 2>&1 || true
    sleep 0.1
}

run_client identity       -i
run_client list_domains   -d
run_client list_test_dom  -t TestDomain
run_client bilateral      -a TestDomain -r Bilateral_Table_ID
run_client dsconditions   -a TestDomain -r DSConditions_Detected
run_client xfer_set       -a TestDomain -r Transfer_Set_Name
run_client next_dsxs      -a TestDomain -r Next_DSTransfer_Set
run_client xfer_report    -a TestDomain -r Transfer_Report_Name
run_client info_msg       -a TestDomain -r Information_Message_1
run_client info_buffer    -a TestDomain -r Info_Buffer_1
run_client program        -a TestDomain -r Program_PCS
run_client event_cond     -a TestDomain -r Event_Condition_1
run_client account        -a TestDomain -r Account_Operator1
run_client timeseries     -a TestDomain -r DSTimeSeries_Hourly
run_client errorlog       -a TestDomain -r Error_Log

# Block 5 Device Control: Select (should transition Idle -> Selected),
# then Operate (Selected -> Operated), then another Device read without
# prior Select on a different device to exercise the "no-select" path.
# ICCP uses underscores in variable names (MMS identifiers don't permit
# '.' outside of component paths, which mms_utility doesn't support).
run_client dev_select_A   -a TestDomain -r Device_Breaker_A_SBOSelect
run_client dev_operate_A  -a TestDomain -r Device_Breaker_A_SBOOperate
run_client dev_orphan_op  -a TestDomain -r Device_Line5_Operate
run_client dev_cancel_A   -a TestDomain -r Device_Breaker_A_Cancel
run_client dev_tag_Z      -a TestDomain -r Device_Switch_Z_TagOperate

# Named Variable List directory read -- exercises GetVariableListDir
# and DSTransfer_Set_ name matching (Block 2).
run_client list_vars      -a TestDomain -z DSTransfer_Set_1

echo "== stop dumpcap =="
sudo kill -INT "$DUMP_PID" 2>/dev/null || true
# Wait for dumpcap to finalize the file.
wait "$DUMP_PID" 2>/dev/null || true

echo "== stop server =="
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

ls -la "$PCAP"
echo
echo "== capinfos =="
capinfos "$PCAP" 2>&1 | head -n 12 || true
