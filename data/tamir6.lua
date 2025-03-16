-- Wireshark Lua static dissector for tamir6
-- This dissector decodes fields according to fixed sizes without DPI tests.

local tamir6 = Proto("tamir6", "tamir6")

local f_sync = ProtoField.uint8("tamir6.sync", "Sync"), base.DEC
local f_id = ProtoField.uint32("tamir6.id", "Id"), base.DEC
local f_type = ProtoField.uint32("tamir6.type", "Type"), base.DEC
local f_length = ProtoField.uint32("tamir6.length", "Length"), base.DEC
local f_payload = ProtoField.string("tamir6.payload", "Payload")
local f_crc = ProtoField.uint32("tamir6.crc", "Crc"), base.DEC
local f_flag = ProtoField.uint8("tamir6.flag", "Flag"), base.DEC

tamir6.fields = { f_sync, f_id, f_type, f_length, f_payload, f_crc, f_flag }

function tamir6.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "tamir6"
    local subtree = tree:add(tamir6, buffer(), "tamir6")
    local offset = 0

    -- Field: sync
    local sync = buffer(offset, 1):uint()
    subtree:add(f_sync, buffer(offset, 1))
    offset = offset + 1

    -- Field: id
    local id = buffer(offset, 4):uint()
    subtree:add(f_id, buffer(offset, 4))
    offset = offset + 4

    -- Field: type
    local type = buffer(offset, 4):uint()
    subtree:add(f_type, buffer(offset, 4))
    offset = offset + 4

    -- Field: length
    local length = buffer(offset, 4):uint()
    subtree:add(f_length, buffer(offset, 4))
    offset = offset + 4

    -- Field: payload
    -- Dynamic array field: payload (length defined by field 'length')
    local dynamic_length = length
    local payload = buffer(offset, dynamic_length):string()
    subtree:add(f_payload, buffer(offset, dynamic_length))
    offset = offset + dynamic_length

    -- Field: crc
    local crc = buffer(offset, 4):uint()
    subtree:add(f_crc, buffer(offset, 4))
    offset = offset + 4

    -- Field: flag
    local flag = buffer(offset, 1):uint()
    subtree:add(f_flag, buffer(offset, 1))
    offset = offset + 1

end

-- Register this dissector to the UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, tamir6)
