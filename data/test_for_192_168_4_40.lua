-- Wireshark Lua dissector for test on IP 192.168.4.40
-- Generated automatically from DPI JSON.

local test_192_168_4_40 = Proto("test_192_168_4_40", "test for IP 192.168.4.40")

local f_down = ProtoField.string("test_192_168_4_40.down", "Down")
local f_up = ProtoField.string("test_192_168_4_40.up", "Up")

test_192_168_4_40.fields = { f_down, f_up }

function test_192_168_4_40.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "test"
    local subtree = tree:add(test_192_168_4_40, buffer(), "test for IP 192.168.4.40")
    local offset = 0
    local dpi_error = false
    local error_messages = {}
    local parsed_values = {}

    -- Field: down
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for down")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for down")
        return
    end
    local down = buffer(offset, 4):string()
    local down_item = subtree:add(f_down, buffer(offset, 4))
    parsed_values['down'] = down
    do
        local min_val = 826474496
        local max_val = 826540032
        if down < min_val or down > max_val then
            down_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for down")
            dpi_error = true
            table.insert(error_messages, "down out of range")
        end
    end
    offset = offset + 4

    -- Field: up
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for up")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for up")
        return
    end
    local up = buffer(offset, 4):string()
    local up_item = subtree:add(f_up, buffer(offset, 4))
    parsed_values['up'] = up
    do
        local min_val = 69271552
        local max_val = 590348288
        if up < min_val or up > max_val then
            up_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for up")
            dpi_error = true
            table.insert(error_messages, "up out of range")
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
udp_port:add(10000, test_192_168_4_40)
