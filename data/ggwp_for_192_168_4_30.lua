-- Wireshark Lua dissector for ggwp on IP 192.168.4.30
-- Generated automatically from DPI JSON.

local ggwp_192_168_4_30 = Proto("ggwp_192_168_4_30", "ggwp for IP 192.168.4.30")

local f_checksum = ProtoField.uint32("ggwp_192_168_4_30.checksum", "Checksum"), base.DEC
local f_end_flag = ProtoField.string("ggwp_192_168_4_30.end_flag", "End_flag")
local f_flag = ProtoField.string("ggwp_192_168_4_30.flag", "Flag")
local f_id = ProtoField.uint32("ggwp_192_168_4_30.id", "Id"), base.DEC
local f_length = ProtoField.uint32("ggwp_192_168_4_30.length", "Length"), base.DEC
local f_message = ProtoField.string("ggwp_192_168_4_30.message", "Message")

ggwp_192_168_4_30.fields = { f_checksum, f_end_flag, f_flag, f_id, f_length, f_message }

function ggwp_192_168_4_30.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "ggwp"
    local subtree = tree:add(ggwp_192_168_4_30, buffer(), "ggwp for IP 192.168.4.30")
    local offset = 0
    local dpi_error = false
    local error_messages = {}
    local parsed_values = {}

    -- Field: checksum
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for checksum")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for checksum")
        return
    end
    local checksum = buffer(offset, 4):uint()
    local checksum_item = subtree:add(f_checksum, buffer(offset, 4))
    parsed_values['checksum'] = checksum
    do
        local min_val = 2930746808
        local max_val = 4037728329
        if checksum < min_val or checksum > max_val then
            checksum_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for checksum")
            dpi_error = true
            table.insert(error_messages, "checksum out of range")
        end
    end
    offset = offset + 4

    -- Field: end_flag
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for end_flag")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for end_flag")
        return
    end
    local end_flag = buffer(offset, 1):string()
    local end_flag_item = subtree:add(f_end_flag, buffer(offset, 1))
    parsed_values['end_flag'] = end_flag
    offset = offset + 1

    -- Field: flag
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for flag")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for flag")
        return
    end
    local flag = buffer(offset, 1):string()
    local flag_item = subtree:add(f_flag, buffer(offset, 1))
    parsed_values['flag'] = flag
    offset = offset + 1

    -- Field: id
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for id")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for id")
        return
    end
    local id = buffer(offset, 4):uint()
    local id_item = subtree:add(f_id, buffer(offset, 4))
    parsed_values['id'] = id
    do
        local min_val = 3317
        local max_val = 4857
        if id < min_val or id > max_val then
            id_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for id")
            dpi_error = true
            table.insert(error_messages, "id out of range")
        end
    end
    offset = offset + 4

    -- Field: length
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for length")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for length")
        return
    end
    local length = buffer(offset, 4):uint()
    local length_item = subtree:add(f_length, buffer(offset, 4))
    parsed_values['length'] = length
    do
        local min_val = 6
        local max_val = 13
        if length < min_val or length > max_val then
            length_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for length")
            dpi_error = true
            table.insert(error_messages, "length out of range")
        end
    end
    offset = offset + 4

    -- Field: message
    local dynamic_length = length
    if dynamic_length < 6 or dynamic_length > 13 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "message length out of range")
        dpi_error = true
        table.insert(error_messages, "message length out of range")
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for message")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for message")
        return
    end
    local message = buffer(offset, dynamic_length):string()
    local message_item = subtree:add(f_message, buffer(offset, dynamic_length))
    parsed_values['message'] = message
    offset = offset + dynamic_length

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
udp_port:add(10000, ggwp_192_168_4_30)
