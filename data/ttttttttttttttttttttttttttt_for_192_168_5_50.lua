-- Wireshark Lua dissector for ttttttttttttttttttttttttttt on IP 192.168.5.50
-- Generated automatically from DPI JSON.

local ttttttttttttttttttttttttttt_192_168_5_50 = Proto("ttttttttttttttttttttttttttt_192_168_5_50", "ttttttttttttttttttttttttttt for IP 192.168.5.50")

local f_a = ProtoField.uint32("ttttttttttttttttttttttttttt_192_168_5_50.a", "A"), base.DEC

ttttttttttttttttttttttttttt_192_168_5_50.fields = { f_a }

function ttttttttttttttttttttttttttt_192_168_5_50.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "ttttttttttttttttttttttttttt"
    local subtree = tree:add(ttttttttttttttttttttttttttt_192_168_5_50, buffer(), "ttttttttttttttttttttttttttt for IP 192.168.5.50")
    local offset = 0
    local dpi_error = false
    local error_messages = {}
    local parsed_values = {}

    -- Field: a
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for a")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for a")
        return
    end
    local a = buffer(offset, 4):uint()
    local a_item = subtree:add(f_a, buffer(offset, 4))
    parsed_values['a'] = a
    do
        local min_val = 1347699532
        local max_val = 1347699532
        if a < min_val or a > max_val then
            a_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for a")
            dpi_error = true
            table.insert(error_messages, "a out of range")
        end
    end
    offset = offset + 4

    if dpi_error then
        local msg = table.concat(error_messages, "; ")
        pinfo.cols.info = "[DPI Error: " .. msg .. "]"
        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, "DPI Error in this packet")
    else
        -- Packet is OK; show a summary of fields in the Info column
        local parts = {}
        for k,v in pairs(parsed_values) do
            table.insert(parts, k .. "=" .. tostring(v))
        end
        table.sort(parts)
        pinfo.cols.info = "" .. table.concat(parts, ", ")
    end
end

-- Register this dissector for UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, ttttttttttttttttttttttttttt_192_168_5_50)
