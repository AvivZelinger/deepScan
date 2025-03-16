-- Wireshark Lua static dissector for protocol_2
-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.

local protocol_2 = Proto("protocol_2", "protocol_2")

local f_checksum = ProtoField.uint32("protocol_2.checksum", "Checksum"), base.DEC
local f_end_flag = ProtoField.string("protocol_2.end_flag", "End_flag")
local f_id = ProtoField.uint32("protocol_2.id", "Id"), base.DEC
local f_length = ProtoField.uint32("protocol_2.length", "Length"), base.DEC

protocol_2.fields = { f_checksum, f_end_flag, f_id, f_length }

function protocol_2.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "protocol_2"
    local subtree = tree:add(protocol_2, buffer(), "protocol_2")
    local offset = 0
    local field_values = {}

    -- Field: checksum
    local checksum = buffer(offset, 4):uint()
    subtree:add(f_checksum, buffer(offset, 4))
    field_values['checksum'] = checksum
    offset = offset + 4

    -- Field: end_flag
    local end_flag = buffer(offset, 1):string()
    subtree:add(f_end_flag, buffer(offset, 1))
    field_values['end_flag'] = end_flag
    offset = offset + 1

    -- Field: id
    local id = buffer(offset, 4):uint()
    subtree:add(f_id, buffer(offset, 4))
    field_values['id'] = id
    offset = offset + 4

    -- Field: length
    local length = buffer(offset, 4):uint()
    subtree:add(f_length, buffer(offset, 4))
    field_values['length'] = length
    offset = offset + 4

    local parts = {}
    for k,v in pairs(field_values) do
        table.insert(parts, k .. "=" .. tostring(v))
    end
    table.sort(parts)
    pinfo.cols.info = "Static: " .. table.concat(parts, ", ")
end

-- Register this dissector for the UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, protocol_2)
