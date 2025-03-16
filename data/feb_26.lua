-- Wireshark Lua static dissector for feb_26
-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.

local feb_26 = Proto("feb_26", "feb_26")

local f_proto_id = ProtoField.string("feb_26.proto_id", "Proto_id")
local f_version = ProtoField.string("feb_26.version", "Version")
local f_msg_type = ProtoField.string("feb_26.msg_type", "Msg_type")
local f_session_id = ProtoField.uint32("feb_26.session_id", "Session_id"), base.DEC
local f_seq_num = ProtoField.uint32("feb_26.seq_num", "Seq_num"), base.DEC
local f_timestamp = ProtoField.string("feb_26.timestamp", "Timestamp")
local f_payload_length = ProtoField.uint32("feb_26.payload_length", "Payload_length"), base.DEC
local f_message_data = ProtoField.string("feb_26.message_data", "Message_data")

feb_26.fields = { f_proto_id, f_version, f_msg_type, f_session_id, f_seq_num, f_timestamp, f_payload_length, f_message_data }

function feb_26.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "feb_26"
    local subtree = tree:add(feb_26, buffer(), "feb_26")
    local offset = 0
    local field_values = {}

    -- Field: proto_id
    local proto_id = buffer(offset, 4):string()
    subtree:add(f_proto_id, buffer(offset, 4))
    field_values['proto_id'] = proto_id
    offset = offset + 4

    -- Field: version
    local version = buffer(offset, 1):string()
    subtree:add(f_version, buffer(offset, 1))
    field_values['version'] = version
    offset = offset + 1

    -- Field: msg_type
    local msg_type = buffer(offset, 1):string()
    subtree:add(f_msg_type, buffer(offset, 1))
    field_values['msg_type'] = msg_type
    offset = offset + 1

    -- Field: session_id
    local session_id = buffer(offset, 4):uint()
    subtree:add(f_session_id, buffer(offset, 4))
    field_values['session_id'] = session_id
    offset = offset + 4

    -- Field: seq_num
    local seq_num = buffer(offset, 4):uint()
    subtree:add(f_seq_num, buffer(offset, 4))
    field_values['seq_num'] = seq_num
    offset = offset + 4

    -- Field: timestamp
    local timestamp = buffer(offset, 8):string()
    subtree:add(f_timestamp, buffer(offset, 8))
    field_values['timestamp'] = timestamp
    offset = offset + 8

    -- Field: payload_length
    local payload_length = buffer(offset, 4):uint()
    subtree:add(f_payload_length, buffer(offset, 4))
    field_values['payload_length'] = payload_length
    offset = offset + 4

    -- Field: message_data
    local dynamic_length = payload_length
    local message_data = buffer(offset, dynamic_length):string()
    subtree:add(f_message_data, buffer(offset, dynamic_length))
    field_values['message_data'] = message_data
    offset = offset + dynamic_length

    local parts = {}
    for k,v in pairs(field_values) do
        table.insert(parts, k .. "=" .. tostring(v))
    end
    table.sort(parts)
    pinfo.cols.info = "Static: " .. table.concat(parts, ", ")
end

-- Register this dissector for the UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, feb_26)
