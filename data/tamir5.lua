-- Wireshark Lua static dissector for tamir5
-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.

local tamir5 = Proto("tamir5", "tamir5")

local f_sync = ProtoField.uint8("tamir5.sync", "Sync"), base.DEC
local f_id = ProtoField.uint32("tamir5.id", "Id"), base.DEC
local f_type = ProtoField.uint32("tamir5.type", "Type"), base.DEC
local f_length = ProtoField.uint32("tamir5.length", "Length"), base.DEC
local f_payload = ProtoField.string("tamir5.payload", "Payload")
local f_crc = ProtoField.uint32("tamir5.crc", "Crc"), base.DEC
local f_flag = ProtoField.uint8("tamir5.flag", "Flag"), base.DEC

tamir5.fields = { f_sync, f_id, f_type, f_length, f_payload, f_crc, f_flag }

function tamir5.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "tamir5"
    local subtree = tree:add(tamir5, buffer(), "tamir5")
    local offset = 0
    local field_values = {}

    -- Field: sync
    local sync = buffer(offset, 1):uint()
    subtree:add(f_sync, buffer(offset, 1))
    field_values['sync'] = sync
    offset = offset + 1

    -- Field: id
    local id = buffer(offset, 4):uint()
    subtree:add(f_id, buffer(offset, 4))
    field_values['id'] = id
    offset = offset + 4

    -- Field: type
    local type = buffer(offset, 4):uint()
    subtree:add(f_type, buffer(offset, 4))
    field_values['type'] = type
    offset = offset + 4

    -- Field: length
    local length = buffer(offset, 4):uint()
    subtree:add(f_length, buffer(offset, 4))
    field_values['length'] = length
    offset = offset + 4

    -- Field: payload
    local dynamic_length = length
    local payload = buffer(offset, dynamic_length):string()
    subtree:add(f_payload, buffer(offset, dynamic_length))
    field_values['payload'] = payload
    offset = offset + dynamic_length

    -- Field: crc
    local crc = buffer(offset, 4):uint()
    subtree:add(f_crc, buffer(offset, 4))
    field_values['crc'] = crc
    offset = offset + 4

    -- Field: flag
    local flag = buffer(offset, 1):uint()
    subtree:add(f_flag, buffer(offset, 1))
    field_values['flag'] = flag
    offset = offset + 1

    local parts = {}
    for k,v in pairs(field_values) do
        table.insert(parts, k .. "=" .. tostring(v))
    end
    table.sort(parts)
    pinfo.cols.info = "Static: " .. table.concat(parts, ", ")
end

-- Register this dissector for the UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, tamir5)
