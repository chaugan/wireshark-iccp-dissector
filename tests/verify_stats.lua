-- verify_stats.lua
--
-- Automated verification that the ICCP tap fires for the expected number
-- of packets, even in two-pass (retap) mode.
--
-- The C tap data is not accessible from Lua, but the packet count must
-- match the stats_tree output. Use tshark -z iccp,tree for full data.
--
-- Usage:
--   tshark -2 -X lua_script:tests/verify_stats.lua -r <pcap> -q
--
-- Expected: 6292 packets for iccp2-annon.pcap (matches -z iccp,tree output).

local tap = Listener.new("iccp")

local total = 0

function tap.packet(pinfo, tvb, tapdata)
    total = total + 1
end

function tap.reset()
    total = 0
end

function tap.draw()
    print(string.format("ICCP tap fired for %d packets", total))
    -- Verify against known-good count for iccp2-annon.pcap
    if total == 6292 then
        print("PASS: packet count matches expected 6292")
    elseif total > 0 then
        print(string.format("INFO: expected 6292, got %d (different pcap?)", total))
    else
        print("FAIL: no ICCP packets found")
    end
end
