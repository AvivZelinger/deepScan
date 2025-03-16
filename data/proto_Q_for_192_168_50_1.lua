-- Wireshark Lua dissector for proto_Q on IP 192.168.50.1
-- Generated automatically from DPI JSON.

local proto_Q_192_168_50_1 = Proto("proto_Q_192_168_50_1", "proto_Q for IP 192.168.50.1")

local f_header = ProtoField.string("proto_Q_192_168_50_1.header", "Header")
local f_version = ProtoField.uint32("proto_Q_192_168_50_1.version", "Version"), base.DEC
local f_flags1 = ProtoField.uint8("proto_Q_192_168_50_1.flags1", "Flags1 (Bitfield)")
local f_flags2 = ProtoField.uint8("proto_Q_192_168_50_1.flags2", "Flags2 (Bitfield)")
local f_temperature = ProtoField.uint32("proto_Q_192_168_50_1.temperature", "Temperature"), base.DEC
local f_pressure = ProtoField.string("proto_Q_192_168_50_1.pressure", "Pressure")
local f_device_id = ProtoField.string("proto_Q_192_168_50_1.device_id", "Device_id")
local f_message_length = ProtoField.uint32("proto_Q_192_168_50_1.message_length", "Message_length"), base.DEC
local f_message = ProtoField.string("proto_Q_192_168_50_1.message", "Message")
local f_checksum = ProtoField.uint32("proto_Q_192_168_50_1.checksum", "Checksum"), base.DEC

proto_Q_192_168_50_1.fields = { f_header, f_version, f_flags1, f_flags2, f_temperature, f_pressure, f_device_id, f_message_length, f_message, f_checksum }

function proto_Q_192_168_50_1.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "proto_Q"
    local subtree = tree:add(proto_Q_192_168_50_1, buffer(), "proto_Q for IP 192.168.50.1")
    local offset = 0
    local dpi_error = false
    local error_messages = {}
    local parsed_values = {}

    -- Helper function to count the number of bits set in a value
    local function popcount(x)
        local count = 0
        while x > 0 do
            count = count + (x % 2)
            x = math.floor(x / 2)
        end
        return count
    end

    -- Helper function to convert a number to a binary string of a given bit length
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
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for header")
        return
    end
    local header = buffer(offset, 4):string()
    local header_item = subtree:add(f_header, buffer(offset, 4))
    parsed_values['header'] = header
    offset = offset + 4

    -- Field: version
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for version")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for version")
        return
    end
    local version = buffer(offset, 4):uint()
    local version_item = subtree:add(f_version, buffer(offset, 4))
    parsed_values['version'] = version
    do
        local min_val = 1
        local max_val = 5
        if version < min_val or version > max_val then
            version_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for version")
            dpi_error = true
            table.insert(error_messages, "version out of range")
        end
    end
    offset = offset + 4

    -- Field: flags1
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for flags1")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for flags1")
        return
    end
    local flags1 = buffer(offset, 1):uint()
    local flags1_item = subtree:add(f_flags1, buffer(offset, 1))
    local num_bits = 1 * 8
    local actual_bit_count = popcount(flags1)
    if actual_bit_count ~= 4 then
        flags1_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Bitfield flags1 expected 4 bits set, got " .. actual_bit_count)
        dpi_error = true
        table.insert(error_messages, "Bitfield flags1 expected 4 bits set, got " .. actual_bit_count)
    end
    local binary_str = to_binary_str(flags1, num_bits)
    flags1_item:append_text(" (" .. binary_str .. ")")
    parsed_values['flags1'] = binary_str
    offset = offset + 1

    -- Field: flags2
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for flags2")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for flags2")
        return
    end
    local flags2 = buffer(offset, 1):uint()
    local flags2_item = subtree:add(f_flags2, buffer(offset, 1))
    local num_bits = 1 * 8
    local actual_bit_count = popcount(flags2)
    if actual_bit_count ~= 4 then
        flags2_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Bitfield flags2 expected 4 bits set, got " .. actual_bit_count)
        dpi_error = true
        table.insert(error_messages, "Bitfield flags2 expected 4 bits set, got " .. actual_bit_count)
    end
    local binary_str = to_binary_str(flags2, num_bits)
    flags2_item:append_text(" (" .. binary_str .. ")")
    parsed_values['flags2'] = binary_str
    offset = offset + 1

    -- Field: temperature
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for temperature")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for temperature")
        return
    end
    local temperature = buffer(offset, 4):uint()
    local temperature_item = subtree:add(f_temperature, buffer(offset, 4))
    parsed_values['temperature'] = temperature
    do
        local min_val = -48.50895690917969
        local max_val = 139.04006958007812
        if temperature < min_val or temperature > max_val then
            temperature_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for temperature")
            dpi_error = true
            table.insert(error_messages, "temperature out of range")
        end
    end
    offset = offset + 4

    -- Field: pressure
    if buffer:len() < offset + 8 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for pressure")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for pressure")
        return
    end
    local pressure = buffer(offset, 8):string()
    local pressure_item = subtree:add(f_pressure, buffer(offset, 8))
    parsed_values['pressure'] = pressure
    offset = offset + 8

    -- Field: device_id
    if buffer:len() < offset + 10 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for device_id")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for device_id")
        return
    end
    local device_id = buffer(offset, 10):string()
    local device_id_item = subtree:add(f_device_id, buffer(offset, 10))
    parsed_values['device_id'] = device_id
    offset = offset + 10

    -- Field: message_length
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for message_length")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for message_length")
        return
    end
    local message_length = buffer(offset, 4):uint()
    local message_length_item = subtree:add(f_message_length, buffer(offset, 4))
    parsed_values['message_length'] = message_length
    do
        local min_val = 6
        local max_val = 20
        if message_length < min_val or message_length > max_val then
            message_length_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for message_length")
            dpi_error = true
            table.insert(error_messages, "message_length out of range")
        end
    end
    offset = offset + 4

    -- Field: message
    local dynamic_length = message_length
    if dynamic_length < 6 or dynamic_length > 20 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "message length out of range")
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for message")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for message")
        return
    end
    local message = buffer(offset, dynamic_length):string()
    local message_item = subtree:add(f_message, buffer(offset, dynamic_length))
    parsed_values['message'] = message
    offset = offset + dynamic_length

    -- Field: checksum
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for checksum")
        dpi_error = true
        table.insert(error_messages, "Not enough bytes for checksum")
        return
    end
    local checksum = buffer(offset, 4):uint()
    local checksum_item = subtree:add(f_checksum, buffer(offset, 4))
    parsed_values['checksum'] = checksum
    do
        local min_val = 276530363
        local max_val = 4109898148
        if checksum < min_val or checksum > max_val then
            checksum_item:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for checksum")
            dpi_error = true
            table.insert(error_messages, "checksum out of range")
        end
    end
    offset = offset + 4

    if dpi_error then
        local msg = table.concat(error_messages, "; ")
        pinfo.cols.info = "[DPI Error: " .. msg .. "]"
        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, "DPI Error in this packet")
    else
        local parts = {}
        for k,v in pairs(parsed_values) do
            table.insert(parts, k .. "=" .. tostring(v))
        end
        table.sort(parts)
        pinfo.cols.info = table.concat(parts, ", ")
    end
end

-- Register this dissector for UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, proto_Q_192_168_50_1)
