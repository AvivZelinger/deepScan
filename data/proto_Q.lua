-- Wireshark Lua static dissector for proto_Q
-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.

local proto_Q = Proto("proto_Q", "proto_Q")

local f_header = ProtoField.string("proto_Q.header", "Header")
local f_version = ProtoField.uint32("proto_Q.version", "Version"), base.DEC
local f_flags1 = ProtoField.uint8("proto_Q.flags1", "Flags1 (Bitfield)")
local f_flags2 = ProtoField.uint8("proto_Q.flags2", "Flags2 (Bitfield)")
local f_temperature = ProtoField.float("proto_Q.temperature", "Temperature (Float)")
local f_pressure = ProtoField.string("proto_Q.pressure", "Pressure")
local f_device_id = ProtoField.string("proto_Q.device_id", "Device_id")
local f_message_length = ProtoField.uint32("proto_Q.message_length", "Message_length"), base.DEC
local f_message = ProtoField.string("proto_Q.message", "Message")
local f_checksum = ProtoField.uint32("proto_Q.checksum", "Checksum"), base.DEC

proto_Q.fields = { f_header, f_version, f_flags1, f_flags2, f_temperature, f_pressure, f_device_id, f_message_length, f_message, f_checksum }

function proto_Q.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "proto_Q"
    local subtree = tree:add(proto_Q, buffer(), "proto_Q")
    local offset = 0
    local field_values = {}

-- Add helper functions for bitfield processing
    local function popcount(x)
        local count = 0
        while x > 0 do
            count = count + (x % 2)
            x = math.floor(x / 2)
        end
        return count
    end

    local function to_binary_str(num, bits)
        local s = ""
        for i = bits - 1, 0, -1 do
            local bit_val = bit.rshift(num, i)
            s = s .. (bit.band(bit_val, 1) == 1 and "1" or "0")
        end
        return s
    end

    -- Field: header
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for header")
        return
    end
    local header = buffer(offset, 4):string()
    subtree:add(f_header, buffer(offset, 4))
    field_values['header'] = header
    offset = offset + 4

    -- Field: version
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for version")
        return
    end
    local version = buffer(offset, 4):uint()
    subtree:add(f_version, buffer(offset, 4))
    field_values['version'] = version
    offset = offset + 4

    -- Field: flags1
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for flags1")
        return
    end
    local flags1 = buffer(offset, 1):uint()
    local flags1_item = subtree:add(f_flags1, buffer(offset, 1))
    local num_bits = 1 * 8
    local binary_str = to_binary_str(flags1, num_bits)
    flags1_item:append_text(" (" .. binary_str .. ")")
    field_values['flags1'] = binary_str
    offset = offset + 1

    -- Field: flags2
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for flags2")
        return
    end
    local flags2 = buffer(offset, 1):uint()
    local flags2_item = subtree:add(f_flags2, buffer(offset, 1))
    local num_bits = 1 * 8
    local binary_str = to_binary_str(flags2, num_bits)
    flags2_item:append_text(" (" .. binary_str .. ")")
    field_values['flags2'] = binary_str
    offset = offset + 1

    -- Field: temperature
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for temperature")
        return
    end
    local temperature = buffer(offset, 4):float()
    subtree:add(f_temperature, buffer(offset, 4))
    field_values['temperature'] = temperature
    offset = offset + 4

    -- Field: pressure
    if buffer:len() < offset + 8 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for pressure")
        return
    end
    local pressure = buffer(offset, 8):string()
    subtree:add(f_pressure, buffer(offset, 8))
    field_values['pressure'] = pressure
    offset = offset + 8

    -- Field: device_id
    if buffer:len() < offset + 10 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for device_id")
        return
    end
    local device_id = buffer(offset, 10):string()
    subtree:add(f_device_id, buffer(offset, 10))
    field_values['device_id'] = device_id
    offset = offset + 10

    -- Field: message_length
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for message_length")
        return
    end
    local message_length = buffer(offset, 4):uint()
    subtree:add(f_message_length, buffer(offset, 4))
    field_values['message_length'] = message_length
    offset = offset + 4

    -- Field: message
    local dynamic_length = message_length
    if dynamic_length < 5 or dynamic_length > 20 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "message length out of range")
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for message")
        return
    end
    local message = buffer(offset, dynamic_length):string()
    subtree:add(f_message, buffer(offset, dynamic_length))
    field_values['message'] = message
    offset = offset + dynamic_length

    -- Field: checksum
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for checksum")
        return
    end
    local checksum = buffer(offset, 4):uint()
    subtree:add(f_checksum, buffer(offset, 4))
    field_values['checksum'] = checksum
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
udp_port:add(10000, proto_Q)
