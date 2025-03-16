-- Wireshark Lua static dissector for sss
-- This dissector decodes fields according to fixed sizes without DPI tests.

local sss = Proto("sss", "sss")

local f_sync = ProtoField.uint8("sss.sync", "Sync"), base.DEC
local f_id = ProtoField.uint32("sss.id", "Id"), base.DEC
local f_type = ProtoField.uint32("sss.type", "Type"), base.DEC
local f_length = ProtoField.uint32("sss.length", "Length"), base.DEC
local f_payload = ProtoField.string("sss.payload", "Payload")
local f_crc = ProtoField.uint32("sss.crc", "Crc"), base.DEC
local f_flag = ProtoField.uint8("sss.flag", "Flag"), base.DEC

sss.fields = { f_sync, f_id, f_type, f_length, f_payload, f_crc, f_flag }

function sss.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "sss"
    local subtree = tree:add(sss, buffer(), "sss")
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

-- Register this dissector to a UDP port (change 10000 to the appropriate port if needed)
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, sss)
