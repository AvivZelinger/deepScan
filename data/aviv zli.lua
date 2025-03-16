-- Wireshark Lua static dissector for aviv zli
-- This dissector decodes fields according to fixed sizes without DPI tests.

local aviv zli = Proto("aviv zli", "aviv zli")

local f_checksum = ProtoField.uint32("aviv zli.checksum", "Checksum"), base.DEC
local f_end_flag = ProtoField.string("aviv zli.end_flag", "End_flag")
local f_flag = ProtoField.string("aviv zli.flag", "Flag")
local f_id = ProtoField.uint32("aviv zli.id", "Id"), base.DEC
local f_length = ProtoField.uint32("aviv zli.length", "Length"), base.DEC
local f_message = ProtoField.string("aviv zli.message", "Message")

aviv zli.fields = { f_checksum, f_end_flag, f_flag, f_id, f_length, f_message }

function aviv zli.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "aviv zli"
    local subtree = tree:add(aviv zli, buffer(), "aviv zli")
    local offset = 0

    -- Field: checksum
    local checksum = buffer(offset, 4):uint()
    subtree:add(f_checksum, buffer(offset, 4))
    offset = offset + 4

    -- Field: end_flag
    local end_flag = buffer(offset, 1):string()
    subtree:add(f_end_flag, buffer(offset, 1))
    offset = offset + 1

    -- Field: flag
    local flag = buffer(offset, 1):string()
    subtree:add(f_flag, buffer(offset, 1))
    offset = offset + 1

    -- Field: id
    local id = buffer(offset, 4):uint()
    subtree:add(f_id, buffer(offset, 4))
    offset = offset + 4

    -- Field: length
    local length = buffer(offset, 4):uint()
    subtree:add(f_length, buffer(offset, 4))
    offset = offset + 4

    -- Field: message
    -- Dynamic array field: message (length defined by field 'length')
    local dynamic_length = length
    local message = buffer(offset, dynamic_length):string()
    subtree:add(f_message, buffer(offset, dynamic_length))
    offset = offset + dynamic_length

end

-- Register this dissector to the UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, aviv zli)
