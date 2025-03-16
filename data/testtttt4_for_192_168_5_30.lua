-- Wireshark Lua dissector for testtttt4 on IP 192.168.5.30
-- Generated automatically from DPI JSON.

local testtttt4_192_168_5_30 = Proto("testtttt4_192_168_5_30", "testtttt4 for IP 192.168.5.30")

local f_signature = ProtoField.string("testtttt4_192_168_5_30.signature", "Signature")
local f_version = ProtoField.uint8("testtttt4_192_168_5_30.version", "Version"), base.DEC
local f_flags = ProtoField.uint8("testtttt4_192_168_5_30.flags", "Flags"), base.DEC
local f_command = ProtoField.string("testtttt4_192_168_5_30.command", "Command")
local f_session_id = ProtoField.uint32("testtttt4_192_168_5_30.session_id", "Session_id"), base.DEC
local f_msg_id = ProtoField.uint32("testtttt4_192_168_5_30.msg_id", "Msg_id"), base.DEC
local f_timestamp = ProtoField.uint64("testtttt4_192_168_5_30.timestamp", "Timestamp"), base.DEC
local f_payload_size = ProtoField.uint32("testtttt4_192_168_5_30.payload_size", "Payload_size"), base.DEC
local f_message = ProtoField.string("testtttt4_192_168_5_30.message", "Message")

testtttt4_192_168_5_30.fields = { f_signature, f_version, f_flags, f_command, f_session_id, f_msg_id, f_timestamp, f_payload_size, f_message }

function testtttt4_192_168_5_30.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "testtttt4"
    local subtree = tree:add(testtttt4_192_168_5_30, buffer(), "testtttt4 for IP 192.168.5.30")
    local offset = 0
    local dpi_error = false
    local error_messages = {}
    local parsed_values = {}

    -- Field: signature
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for signature")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for signature")
        return
    end
    local signature = buffer(offset, 4):string()
    local signature_item = subtree:add(f_signature, buffer(offset, 4))
    parsed_values['signature'] = signature
    offset = offset + 4

    -- Field: version
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for version")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for version")
        return
    end
    local version = buffer(offset, 1):uint()
    local version_item = subtree:add(f_version, buffer(offset, 1))
    parsed_values['version'] = version
    do
        local min_val = 1
        local max_val = 3
        if version < min_val or version > max_val then
            version_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for version")
            dpi_error = true
            table.insert(error_messages, "version out of range")
        end
    end
    offset = offset + 1

    -- Field: flags
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for flags")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for flags")
        return
    end
    local flags = buffer(offset, 1):uint()
    local flags_item = subtree:add(f_flags, buffer(offset, 1))
    parsed_values['flags'] = flags
    do
        local min_val = 0
        local max_val = 3
        if flags < min_val or flags > max_val then
            flags_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for flags")
            dpi_error = true
            table.insert(error_messages, "flags out of range")
        end
    end
    offset = offset + 1

    -- Field: command
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for command")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for command")
        return
    end
    local command = buffer(offset, 1):string()
    local command_item = subtree:add(f_command, buffer(offset, 1))
    parsed_values['command'] = command
    offset = offset + 1

    -- Field: session_id
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for session_id")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for session_id")
        return
    end
    local session_id = buffer(offset, 4):uint()
    local session_id_item = subtree:add(f_session_id, buffer(offset, 4))
    parsed_values['session_id'] = session_id
    do
        local min_val = 1020
        local max_val = 9995
        if session_id < min_val or session_id > max_val then
            session_id_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for session_id")
            dpi_error = true
            table.insert(error_messages, "session_id out of range")
        end
    end
    offset = offset + 4

    -- Field: msg_id
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for msg_id")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for msg_id")
        return
    end
    local msg_id = buffer(offset, 4):uint()
    local msg_id_item = subtree:add(f_msg_id, buffer(offset, 4))
    parsed_values['msg_id'] = msg_id
    do
        local min_val = 22
        local max_val = 9996
        if msg_id < min_val or msg_id > max_val then
            msg_id_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for msg_id")
            dpi_error = true
            table.insert(error_messages, "msg_id out of range")
        end
    end
    offset = offset + 4

    -- Field: timestamp
    if buffer:len() < offset + 8 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for timestamp")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for timestamp")
        return
    end
    local timestamp = buffer(offset, 8):uint()
    local timestamp_item = subtree:add(f_timestamp, buffer(offset, 8))
    parsed_values['timestamp'] = timestamp
    do
        local min_val = 1740858404906
        local max_val = 1740858405811
        if timestamp < min_val or timestamp > max_val then
            timestamp_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for timestamp")
            dpi_error = true
            table.insert(error_messages, "timestamp out of range")
        end
    end
    offset = offset + 8

    -- Field: payload_size
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for payload_size")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for payload_size")
        return
    end
    local payload_size = buffer(offset, 4):uint()
    local payload_size_item = subtree:add(f_payload_size, buffer(offset, 4))
    parsed_values['payload_size'] = payload_size
    do
        local min_val = 5
        local max_val = 15
        if payload_size < min_val or payload_size > max_val then
            payload_size_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for payload_size")
            dpi_error = true
            table.insert(error_messages, "payload_size out of range")
        end
    end
    offset = offset + 4

    -- Field: message
    local dynamic_length = payload_size
    if dynamic_length < 5 or dynamic_length > 15 then
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
udp_port:add(10000, testtttt4_192_168_5_30)
