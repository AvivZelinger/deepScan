-- Wireshark Lua dissector for s on IP 192.168.2.40
-- This file was generated automatically from the DPI JSON description.

local s_192_168_2_40 = Proto("s_192_168_2_40", "s for IP 192.168.2.40")

local f_header = ProtoField.string("s_192_168_2_40.header", "Header")
local f_version = ProtoField.uint8("s_192_168_2_40.version", "Version"), base.DEC
local f_msg_type = ProtoField.string("s_192_168_2_40.msg_type", "Msg_type")
local f_seq = ProtoField.uint32("s_192_168_2_40.seq", "Seq"), base.DEC
local f_payload_size = ProtoField.uint16("s_192_168_2_40.payload_size", "Payload_size"), base.DEC
local f_payload = ProtoField.string("s_192_168_2_40.payload", "Payload")
local f_timestamp = ProtoField.uint32("s_192_168_2_40.timestamp", "Timestamp"), base.DEC
local f_source = ProtoField.string("s_192_168_2_40.source", "Source")
local f_destination = ProtoField.string("s_192_168_2_40.destination", "Destination")
local f_checksum = ProtoField.uint32("s_192_168_2_40.checksum", "Checksum"), base.DEC

s_192_168_2_40.fields = { f_header, f_version, f_msg_type, f_seq, f_payload_size, f_payload, f_timestamp, f_source, f_destination, f_checksum }

function s_192_168_2_40.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "s (192.168.2.40)"
    local subtree = tree:add(s_192_168_2_40, buffer(), "s for IP 192.168.2.40")
    local offset = 0
    local dpi_error = false  -- flag to indicate any DPI test failure

    -- Field: header
    if buffer:len() < offset + 2 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field header")
        dpi_error = true
        return
    end
    local header = buffer(offset, 2):string()
    local header_tree = subtree:add(f_header, buffer(offset, 2))
    if header < 191 or header > 935 then
        header_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field header")
        dpi_error = true
    end
    offset = offset + 2

    -- Field: version
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field version")
        dpi_error = true
        return
    end
    local version = buffer(offset, 1):uint()
    local version_tree = subtree:add(f_version, buffer(offset, 1))
    if version < 1 or version > 3 then
        version_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field version")
        dpi_error = true
    end
    offset = offset + 1

    -- Field: msg_type
    if buffer:len() < offset + 10 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field msg_type")
        dpi_error = true
        return
    end
    local msg_type = buffer(offset, 10):string()
    local msg_type_tree = subtree:add(f_msg_type, buffer(offset, 10))
    offset = offset + 10

    -- Field: seq
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field seq")
        dpi_error = true
        return
    end
    local seq = buffer(offset, 4):uint()
    local seq_tree = subtree:add(f_seq, buffer(offset, 4))
    if seq < 1911 or seq > 9737 then
        seq_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field seq")
        dpi_error = true
    end
    offset = offset + 4

    -- Field: payload_size
    if buffer:len() < offset + 2 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field payload_size")
        dpi_error = true
        return
    end
    local payload_size = buffer(offset, 2):uint()
    local payload_size_tree = subtree:add(f_payload_size, buffer(offset, 2))
    if payload_size < 5 or payload_size > 20 then
        payload_size_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field payload_size")
        dpi_error = true
    end
    offset = offset + 2

    -- Field: payload
    -- Dynamic array field: payload (length defined by field 'None')
    local dynamic_length = None
    if dynamic_length < -10 or dynamic_length > 5 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Dynamic field payload length (" .. dynamic_length .. ") out of allowed range")
        dpi_error = true
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for dynamic field payload")
        dpi_error = true
        return
    end
    local payload = buffer(offset, dynamic_length):string()
    local payload_tree = subtree:add(f_payload, buffer(offset, dynamic_length))
    offset = offset + dynamic_length

    -- Field: timestamp
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field timestamp")
        dpi_error = true
        return
    end
    local timestamp = buffer(offset, 4):uint()
    local timestamp_tree = subtree:add(f_timestamp, buffer(offset, 4))
    if timestamp < 1.2374053985343151e-39 or timestamp > 7.762642160799393e+34 then
        timestamp_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field timestamp")
        dpi_error = true
    end
    offset = offset + 4

    -- Field: source
    if buffer:len() < offset + 15 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field source")
        dpi_error = true
        return
    end
    local source = buffer(offset, 15):string()
    local source_tree = subtree:add(f_source, buffer(offset, 15))
    offset = offset + 15

    -- Field: destination
    if buffer:len() < offset + 15 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field destination")
        dpi_error = true
        return
    end
    local destination = buffer(offset, 15):string()
    local destination_tree = subtree:add(f_destination, buffer(offset, 15))
    offset = offset + 15

    -- Field: checksum
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field checksum")
        dpi_error = true
        return
    end
    local checksum = buffer(offset, 4):uint()
    local checksum_tree = subtree:add(f_checksum, buffer(offset, 4))
    if checksum < 860 or checksum > 57416 then
        checksum_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field checksum")
        dpi_error = true
    end
    offset = offset + 4

    if dpi_error then
        pinfo.cols.info:append(" [DPI Error]")
        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, "DPI Error in this packet")
    end
end

-- Register this dissector to a UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, s_192_168_2_40)
