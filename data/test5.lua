-- Wireshark Lua static dissector for test5
-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.

local test5 = Proto("test5", "test5")

local f_signature = ProtoField.string("test5.signature", "Signature")
local f_version = ProtoField.uint8("test5.version", "Version"), base.DEC
local f_flags = ProtoField.uint8("test5.flags", "Flags"), base.DEC
local f_command = ProtoField.string("test5.command", "Command")
local f_session_id = ProtoField.uint32("test5.session_id", "Session_id"), base.DEC
local f_msg_id = ProtoField.uint32("test5.msg_id", "Msg_id"), base.DEC
local f_timestamp = ProtoField.uint64("test5.timestamp", "Timestamp"), base.DEC
local f_payload_size = ProtoField.uint32("test5.payload_size", "Payload_size"), base.DEC
local f_message = ProtoField.string("test5.message", "Message")

test5.fields = { f_signature, f_version, f_flags, f_command, f_session_id, f_msg_id, f_timestamp, f_payload_size, f_message }

function test5.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "test5"
    local subtree = tree:add(test5, buffer(), "test5")
    local offset = 0
    local field_values = {}

    -- Field: signature
    local signature = buffer(offset, 4):string()
    subtree:add(f_signature, buffer(offset, 4))
    field_values['signature'] = signature
    offset = offset + 4

    -- Field: version
    local version = buffer(offset, 1):uint()
    subtree:add(f_version, buffer(offset, 1))
    field_values['version'] = version
    offset = offset + 1

    -- Field: flags
    local flags = buffer(offset, 1):uint()
    subtree:add(f_flags, buffer(offset, 1))
    field_values['flags'] = flags
    offset = offset + 1

    -- Field: command
    local command = buffer(offset, 1):string()
    subtree:add(f_command, buffer(offset, 1))
    field_values['command'] = command
    offset = offset + 1

    -- Field: session_id
    local session_id = buffer(offset, 4):uint()
    subtree:add(f_session_id, buffer(offset, 4))
    field_values['session_id'] = session_id
    offset = offset + 4

    -- Field: msg_id
    local msg_id = buffer(offset, 4):uint()
    subtree:add(f_msg_id, buffer(offset, 4))
    field_values['msg_id'] = msg_id
    offset = offset + 4

    -- Field: timestamp
    local timestamp = buffer(offset, 8):uint()
    subtree:add(f_timestamp, buffer(offset, 8))
    field_values['timestamp'] = timestamp
    offset = offset + 8

    -- Field: payload_size
    local payload_size = buffer(offset, 4):uint()
    subtree:add(f_payload_size, buffer(offset, 4))
    field_values['payload_size'] = payload_size
    offset = offset + 4

    -- Field: message
    local dynamic_length = payload_size
    local message = buffer(offset, dynamic_length):string()
    subtree:add(f_message, buffer(offset, dynamic_length))
    field_values['message'] = message
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
udp_port:add(10000, test5)
