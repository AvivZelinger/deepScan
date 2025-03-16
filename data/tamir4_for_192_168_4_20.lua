-- Wireshark Lua dissector for tamir4 on IP 192.168.4.20
-- This file was generated automatically from the DPI JSON description.

local tamir4_192_168_4_20 = Proto("tamir4_192_168_4_20", "tamir4 for IP 192.168.4.20")

local f_sync = ProtoField.uint8("tamir4_192_168_4_20.sync", "Sync"), base.DEC
local f_id = ProtoField.uint32("tamir4_192_168_4_20.id", "Id"), base.DEC
local f_type = ProtoField.uint32("tamir4_192_168_4_20.type", "Type"), base.DEC
local f_length = ProtoField.uint32("tamir4_192_168_4_20.length", "Length"), base.DEC
local f_payload = ProtoField.string("tamir4_192_168_4_20.payload", "Payload")
local f_crc = ProtoField.uint32("tamir4_192_168_4_20.crc", "Crc"), base.DEC
local f_flag = ProtoField.uint8("tamir4_192_168_4_20.flag", "Flag"), base.DEC

tamir4_192_168_4_20.fields = { f_sync, f_id, f_type, f_length, f_payload, f_crc, f_flag }

function tamir4_192_168_4_20.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    local parsed_fields = {}
    local subtree = tree:add(tamir4_192_168_4_20, buffer())
    local offset = 0
    local dpi_error = false
    local error_messages = {}

    local function store_field_value(name, val)
        table.insert(parsed_fields, name.."="..tostring(val))
    end

    -- Field: sync
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field sync")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for sync")
        return
    end

    local sync = buffer(offset, 1):uint()
    local sync_tree = subtree:add(f_sync, buffer(offset, 1))
    local min_val = 0
    local max_val = 1
    if sync < min_val or sync > max_val then
        sync_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for sync")
        dpi_error = true
        table.insert(error_messages, "sync out of range")
    end

    store_field_value("sync", sync)
    offset = offset + 1

    -- Field: id
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field id")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for id")
        return
    end

    local id = buffer(offset, 4):uint()
    local id_tree = subtree:add(f_id, buffer(offset, 4))
    if id < 1687 or id > 8780 then
        id_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for id")
        dpi_error = true
        table.insert(error_messages, "id out of range")
    end

    store_field_value("id", id)
    offset = offset + 4

    -- Field: type
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field type")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for type")
        return
    end

    local type = buffer(offset, 4):uint()
    local type_tree = subtree:add(f_type, buffer(offset, 4))

    store_field_value("type", type)
    offset = offset + 4

    -- Field: length
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field length")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for length")
        return
    end

    local length = buffer(offset, 4):uint()
    local length_tree = subtree:add(f_length, buffer(offset, 4))
    if length < 5 or length > 13 then
        length_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for length")
        dpi_error = true
        table.insert(error_messages, "length out of range")
    end

    store_field_value("length", length)
    offset = offset + 4

    -- Field: payload
    local dynamic_length = length
    if dynamic_length < 5 or dynamic_length > 13 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Dynamic field payload length out of allowed range")
        dpi_error = true
        table.insert(error_messages, "payload length out of range")
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for dynamic field payload")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for payload")
        return
    end

    local payload = buffer(offset, dynamic_length):string()
    local payload_tree = subtree:add(f_payload, buffer(offset, dynamic_length))
    store_field_value("payload", payload)
    offset = offset + dynamic_length

    -- Field: crc
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field crc")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for crc")
        return
    end

    local crc = buffer(offset, 4):uint()
    local crc_tree = subtree:add(f_crc, buffer(offset, 4))
    if crc < 113595184 or crc > 3785047226 then
        crc_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for crc")
        dpi_error = true
        table.insert(error_messages, "crc out of range")
    end

    store_field_value("crc", crc)
    offset = offset + 4

    -- Field: flag
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field flag")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for flag")
        return
    end

    local flag = buffer(offset, 1):uint()
    local flag_tree = subtree:add(f_flag, buffer(offset, 1))
    local min_val = 0
    local max_val = 1
    if flag < min_val or flag > max_val then
        flag_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for flag")
        dpi_error = true
        table.insert(error_messages, "flag out of range")
    end

    store_field_value("flag", flag)
    offset = offset + 1

    if dpi_error then
        local msg = table.concat(error_messages, "; ")
        pinfo.cols.info = "[Error: " .. msg .. "]"
        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, "DPI Error in this packet")
    else
        -- Build a string of the parsed field values, e.g. id=123, length=7, etc.
        local details = table.concat(parsed_fields, ", ")
        pinfo.cols.info = "Protocol: tamir4 " .. details
    end
end

-- Register this dissector to a UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, tamir4_192_168_4_20)
