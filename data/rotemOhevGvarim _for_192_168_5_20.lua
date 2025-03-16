-- Wireshark Lua dissector for rotemOhevGvarim  on IP 192.168.5.20
-- Generated automatically from DPI JSON.

local rotemOhevGvarim _192_168_5_20 = Proto("rotemOhevGvarim _192_168_5_20", "rotemOhevGvarim  for IP 192.168.5.20")

local f_proto_id = ProtoField.string("rotemOhevGvarim _192_168_5_20.proto_id", "Proto_id")
local f_version = ProtoField.uint8("rotemOhevGvarim _192_168_5_20.version", "Version"), base.DEC
local f_msg_type = ProtoField.string("rotemOhevGvarim _192_168_5_20.msg_type", "Msg_type")
local f_session_id = ProtoField.uint32("rotemOhevGvarim _192_168_5_20.session_id", "Session_id"), base.DEC
local f_seq_num = ProtoField.uint32("rotemOhevGvarim _192_168_5_20.seq_num", "Seq_num"), base.DEC
local f_timestamp = ProtoField.uint64("rotemOhevGvarim _192_168_5_20.timestamp", "Timestamp"), base.DEC
local f_payload_length = ProtoField.uint32("rotemOhevGvarim _192_168_5_20.payload_length", "Payload_length"), base.DEC
local f_message_data = ProtoField.string("rotemOhevGvarim _192_168_5_20.message_data", "Message_data")

rotemOhevGvarim _192_168_5_20.fields = { f_proto_id, f_version, f_msg_type, f_session_id, f_seq_num, f_timestamp, f_payload_length, f_message_data }

function rotemOhevGvarim _192_168_5_20.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "rotemOhevGvarim "
    local subtree = tree:add(rotemOhevGvarim _192_168_5_20, buffer(), "rotemOhevGvarim  for IP 192.168.5.20")
    local offset = 0
    local dpi_error = false
    local error_messages = {}
    local parsed_values = {}

    -- Field: proto_id
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for proto_id")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for proto_id")
        return
    end
    local proto_id = buffer(offset, 4):string()
    local proto_id_item = subtree:add(f_proto_id, buffer(offset, 4))
    parsed_values['proto_id'] = proto_id
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

    -- Field: msg_type
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for msg_type")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for msg_type")
        return
    end
    local msg_type = buffer(offset, 1):string()
    local msg_type_item = subtree:add(f_msg_type, buffer(offset, 1))
    parsed_values['msg_type'] = msg_type
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
        local min_val = 1308
        local max_val = 8980
        if session_id < min_val or session_id > max_val then
            session_id_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for session_id")
            dpi_error = true
            table.insert(error_messages, "session_id out of range")
        end
    end
    offset = offset + 4

    -- Field: seq_num
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for seq_num")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for seq_num")
        return
    end
    local seq_num = buffer(offset, 4):uint()
    local seq_num_item = subtree:add(f_seq_num, buffer(offset, 4))
    parsed_values['seq_num'] = seq_num
    do
        local min_val = 1290
        local max_val = 9553
        if seq_num < min_val or seq_num > max_val then
            seq_num_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for seq_num")
            dpi_error = true
            table.insert(error_messages, "seq_num out of range")
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
        local min_val = 1740589396027
        local max_val = 1740589396112
        if timestamp < min_val or timestamp > max_val then
            timestamp_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for timestamp")
            dpi_error = true
            table.insert(error_messages, "timestamp out of range")
        end
    end
    offset = offset + 8

    -- Field: payload_length
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for payload_length")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for payload_length")
        return
    end
    local payload_length = buffer(offset, 4):uint()
    local payload_length_item = subtree:add(f_payload_length, buffer(offset, 4))
    parsed_values['payload_length'] = payload_length
    do
        local min_val = 5
        local max_val = 15
        if payload_length < min_val or payload_length > max_val then
            payload_length_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for payload_length")
            dpi_error = true
            table.insert(error_messages, "payload_length out of range")
        end
    end
    offset = offset + 4

    -- Field: message_data
    local dynamic_length = payload_length
    if dynamic_length < 5 or dynamic_length > 15 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "message_data length out of range")
        dpi_error = true
        table.insert(error_messages, "message_data length out of range")
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for message_data")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for message_data")
        return
    end
    local message_data = buffer(offset, dynamic_length):string()
    local message_data_item = subtree:add(f_message_data, buffer(offset, dynamic_length))
    parsed_values['message_data'] = message_data
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
udp_port:add(10000, rotemOhevGvarim _192_168_5_20)
