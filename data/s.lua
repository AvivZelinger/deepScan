-- Wireshark Lua static dissector for s
-- This dissector decodes fields according to fixed sizes without DPI tests.

local s = Proto("s", "s")

local f_header = ProtoField.string("s.header", "Header")
local f_version = ProtoField.uint8("s.version", "Version"), base.DEC
local f_msg_type = ProtoField.string("s.msg_type", "Msg_type")
local f_seq = ProtoField.uint32("s.seq", "Seq"), base.DEC
local f_payload_size = ProtoField.uint16("s.payload_size", "Payload_size"), base.DEC
local f_payload = ProtoField.string("s.payload", "Payload")
local f_timestamp = ProtoField.uint32("s.timestamp", "Timestamp"), base.DEC
local f_source = ProtoField.string("s.source", "Source")
local f_destination = ProtoField.string("s.destination", "Destination")
local f_checksum = ProtoField.uint32("s.checksum", "Checksum"), base.DEC

s.fields = { f_header, f_version, f_msg_type, f_seq, f_payload_size, f_payload, f_timestamp, f_source, f_destination, f_checksum }

function s.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "s"
    local subtree = tree:add(s, buffer(), "s")
    local offset = 0

    -- Field: header
    local header = buffer(offset, 2):string()
    subtree:add(f_header, buffer(offset, 2))
    offset = offset + 2

    -- Field: version
    local version = buffer(offset, 1):uint()
    subtree:add(f_version, buffer(offset, 1))
    offset = offset + 1

    -- Field: msg_type
    local msg_type = buffer(offset, 10):string()
    subtree:add(f_msg_type, buffer(offset, 10))
    offset = offset + 10

    -- Field: seq
    local seq = buffer(offset, 4):uint()
    subtree:add(f_seq, buffer(offset, 4))
    offset = offset + 4

    -- Field: payload_size
    local payload_size = buffer(offset, 2):uint()
    subtree:add(f_payload_size, buffer(offset, 2))
    offset = offset + 2

    -- Field: payload
    -- Dynamic array field: payload (length defined by field 'None')
    local dynamic_length = None
    local payload = buffer(offset, dynamic_length):string()
    subtree:add(f_payload, buffer(offset, dynamic_length))
    offset = offset + dynamic_length

    -- Field: timestamp
    local timestamp = buffer(offset, 4):uint()
    subtree:add(f_timestamp, buffer(offset, 4))
    offset = offset + 4

    -- Field: source
    local source = buffer(offset, 15):string()
    subtree:add(f_source, buffer(offset, 15))
    offset = offset + 15

    -- Field: destination
    local destination = buffer(offset, 15):string()
    subtree:add(f_destination, buffer(offset, 15))
    offset = offset + 15

    -- Field: checksum
    local checksum = buffer(offset, 4):uint()
    subtree:add(f_checksum, buffer(offset, 4))
    offset = offset + 4

end

-- Register this dissector to the UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, s)
