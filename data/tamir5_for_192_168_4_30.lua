-- Wireshark Lua dissector for tamir5 on IP 192.168.4.30
-- Generated automatically from DPI JSON.

local tamir5_192_168_4_30 = Proto("tamir5_192_168_4_30", "tamir5 for IP 192.168.4.30")

local f_sync = ProtoField.uint8("tamir5_192_168_4_30.sync", "Sync"), base.DEC
local f_id = ProtoField.uint32("tamir5_192_168_4_30.id", "Id"), base.DEC
local f_type = ProtoField.uint32("tamir5_192_168_4_30.type", "Type"), base.DEC
local f_length = ProtoField.uint32("tamir5_192_168_4_30.length", "Length"), base.DEC
local f_payload = ProtoField.string("tamir5_192_168_4_30.payload", "Payload")
local f_crc = ProtoField.uint32("tamir5_192_168_4_30.crc", "Crc"), base.DEC
local f_flag = ProtoField.uint8("tamir5_192_168_4_30.flag", "Flag"), base.DEC

tamir5_192_168_4_30.fields = { f_sync, f_id, f_type, f_length, f_payload, f_crc, f_flag }

function tamir5_192_168_4_30.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "tamir5"
    local subtree = tree:add(tamir5_192_168_4_30, buffer(), "tamir5 for IP 192.168.4.30")
    local offset = 0
    local dpi_error = false
    local error_messages = {}
    local parsed_values = {}

    -- Field: sync
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for sync")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for sync")
        return
    end
    local sync = buffer(offset, 1):uint()
    local sync_item = subtree:add(f_sync, buffer(offset, 1))
    parsed_values['sync'] = sync
    do
        local min_val = 0
        local max_val = 1
        if sync < min_val or sync > max_val then
            sync_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for sync")
            dpi_error = true
            table.insert(error_messages, "sync out of range")
        end
    end
    offset = offset + 1

    -- Field: id
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for id")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for id")
        return
    end
    local id = buffer(offset, 4):uint()
    local id_item = subtree:add(f_id, buffer(offset, 4))
    parsed_values['id'] = id
    do
        local min_val = 1660
        local max_val = 8445
        if id < min_val or id > max_val then
            id_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for id")
            dpi_error = true
            table.insert(error_messages, "id out of range")
        end
    end
    offset = offset + 4

    -- Field: type
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for type")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for type")
        return
    end
    local type = buffer(offset, 4):uint()
    local type_item = subtree:add(f_type, buffer(offset, 4))
    parsed_values['type'] = type
    offset = offset + 4

    -- Field: length
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for length")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for length")
        return
    end
    local length = buffer(offset, 4):uint()
    local length_item = subtree:add(f_length, buffer(offset, 4))
    parsed_values['length'] = length
    do
        local min_val = 5
        local max_val = 14
        if length < min_val or length > max_val then
            length_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for length")
            dpi_error = true
            table.insert(error_messages, "length out of range")
        end
    end
    offset = offset + 4

    -- Field: payload
    local dynamic_length = length
    if dynamic_length < 5 or dynamic_length > 14 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "payload length out of range")
        dpi_error = true
        table.insert(error_messages, "payload length out of range")
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for payload")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for payload")
        return
    end
    local payload = buffer(offset, dynamic_length):string()
    local payload_item = subtree:add(f_payload, buffer(offset, dynamic_length))
    parsed_values['payload'] = payload
    offset = offset + dynamic_length

    -- Field: crc
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for crc")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for crc")
        return
    end
    local crc = buffer(offset, 4):uint()
    local crc_item = subtree:add(f_crc, buffer(offset, 4))
    parsed_values['crc'] = crc
    do
        local min_val = 511249907
        local max_val = 4178386961
        if crc < min_val or crc > max_val then
            crc_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for crc")
            dpi_error = true
            table.insert(error_messages, "crc out of range")
        end
    end
    offset = offset + 4

    -- Field: flag
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for flag")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for flag")
        return
    end
    local flag = buffer(offset, 1):uint()
    local flag_item = subtree:add(f_flag, buffer(offset, 1))
    parsed_values['flag'] = flag
    do
        local min_val = 0
        local max_val = 1
        if flag < min_val or flag > max_val then
            flag_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for flag")
            dpi_error = true
            table.insert(error_messages, "flag out of range")
        end
    end
    offset = offset + 1

    if dpi_error then
        local msg = table.concat(error_messages, "; ")
        pinfo.cols.info = "[DPI Error: " .. msg .. "]"
        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, "DPI Error in this packet")
    else
        -- Packet is OK; show a summary of fields in the Info column
        local parts = {}
        for k,v in pairs(parsed_values) do
            table.insert(parts, k .. "=" .. tostring(v))
        end
        table.sort(parts)
        pinfo.cols.info = "" .. table.concat(parts, ", ")
    end
end

-- Register this dissector for UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, tamir5_192_168_4_30)
