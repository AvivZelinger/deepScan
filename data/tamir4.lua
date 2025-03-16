-- Wireshark Lua static dissector for tamir4
-- This dissector decodes fields according to fixed sizes without DPI tests.

local tamir4 = Proto("tamir4", "tamir4")

local f_sync = ProtoField.uint8("tamir4.sync", "Sync"), base.DEC
local f_id = ProtoField.uint32("tamir4.id", "Id"), base.DEC
local f_type = ProtoField.uint32("tamir4.type", "Type"), base.DEC
local f_length = ProtoField.uint32("tamir4.length", "Length"), base.DEC
local f_payload = ProtoField.string("tamir4.payload", "Payload")
local f_crc = ProtoField.uint32("tamir4.crc", "Crc"), base.DEC
local f_flag = ProtoField.uint8("tamir4.flag", "Flag"), base.DEC

tamir4.fields = { f_sync, f_id, f_type, f_length, f_payload, f_crc, f_flag }

function tamir4.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "tamir4"
    local subtree = tree:add(tamir4, buffer())
    local offset = 0
    local field_values = {}

    local function store_static_value(name, val)
        table.insert(field_values, name.."="..tostring(val))
    end

    -- Field: sync
    if buffer:len() < offset + 1 then return end
    local sync = buffer(offset, 1):uint()
    subtree:add(f_sync, buffer(offset, 1))
    store_static_value("sync", sync)
    offset = offset + 1

    -- Field: id
    if buffer:len() < offset + 4 then return end
    local id = buffer(offset, 4):uint()
    subtree:add(f_id, buffer(offset, 4))
    store_static_value("id", id)
    offset = offset + 4

    -- Field: type
    if buffer:len() < offset + 4 then return end
    local type = buffer(offset, 4):uint()
    subtree:add(f_type, buffer(offset, 4))
    store_static_value("type", type)
    offset = offset + 4

    -- Field: length
    if buffer:len() < offset + 4 then return end
    local length = buffer(offset, 4):uint()
    subtree:add(f_length, buffer(offset, 4))
    store_static_value("length", length)
    offset = offset + 4

    -- Field: payload
    local dynamic_length = length
    if buffer:len() < offset + dynamic_length then return end
    local payload = buffer(offset, dynamic_length):string()
    subtree:add(f_payload, buffer(offset, dynamic_length))
    store_static_value("payload", payload)
    offset = offset + dynamic_length

    -- Field: crc
    if buffer:len() < offset + 4 then return end
    local crc = buffer(offset, 4):uint()
    subtree:add(f_crc, buffer(offset, 4))
    store_static_value("crc", crc)
    offset = offset + 4

    -- Field: flag
    if buffer:len() < offset + 1 then return end
    local flag = buffer(offset, 1):uint()
    subtree:add(f_flag, buffer(offset, 1))
    store_static_value("flag", flag)
    offset = offset + 1

    -- Finally, set the Info column to show the field values
    local details = table.concat(field_values, ", ")
    pinfo.cols.info = "Protocol: tamir4 (static) " .. details
end

-- Register this dissector to the UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, tamir4)
