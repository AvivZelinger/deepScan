-- Wireshark Lua static dissector for ggwp
-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.

local ggwp = Proto("ggwp", "ggwp")

local f_checksum = ProtoField.uint32("ggwp.checksum", "Checksum"), base.DEC
local f_end_flag = ProtoField.string("ggwp.end_flag", "End_flag")
local f_flag = ProtoField.string("ggwp.flag", "Flag")
local f_id = ProtoField.uint32("ggwp.id", "Id"), base.DEC
local f_length = ProtoField.uint32("ggwp.length", "Length"), base.DEC
local f_message = ProtoField.string("ggwp.message", "Message")

ggwp.fields = { f_checksum, f_end_flag, f_flag, f_id, f_length, f_message }

function ggwp.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "ggwp"
    local subtree = tree:add(ggwp, buffer(), "ggwp")
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

    -- Field: flag
    local flag = buffer(offset, 1):string()
    subtree:add(f_flag, buffer(offset, 1))
    field_values['flag'] = flag
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

    -- Field: message
    local dynamic_length = length
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
udp_port:add(10000, ggwp)
