-- Wireshark Lua dissector for aviv zli on IP 192.168.4.50
-- This file was generated automatically from the DPI JSON description.

local aviv zli_192_168_4_50 = Proto("aviv zli_192_168_4_50", "aviv zli for IP 192.168.4.50")

local f_checksum = ProtoField.uint32("aviv zli_192_168_4_50.checksum", "Checksum"), base.DEC
local f_end_flag = ProtoField.string("aviv zli_192_168_4_50.end_flag", "End_flag")
local f_flag = ProtoField.string("aviv zli_192_168_4_50.flag", "Flag")
local f_id = ProtoField.uint32("aviv zli_192_168_4_50.id", "Id"), base.DEC
local f_length = ProtoField.uint32("aviv zli_192_168_4_50.length", "Length"), base.DEC
local f_message = ProtoField.string("aviv zli_192_168_4_50.message", "Message")

aviv zli_192_168_4_50.fields = { f_checksum, f_end_flag, f_flag, f_id, f_length, f_message }

function aviv zli_192_168_4_50.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "aviv zli (192.168.4.50)"
    local subtree = tree:add(aviv zli_192_168_4_50, buffer(), "aviv zli for IP 192.168.4.50")
    local offset = 0
    local dpi_error = false  -- flag to indicate any DPI test failure

    -- Field: checksum
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field checksum")
        dpi_error = true
        return
    end
    local checksum = buffer(offset, 4):uint()
    local checksum_tree = subtree:add(f_checksum, buffer(offset, 4))
    if checksum < 280928825 or checksum > 4208399043 then
        checksum_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field checksum")
        dpi_error = true
    end
    offset = offset + 4

    -- Field: end_flag
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field end_flag")
        dpi_error = true
        return
    end
    local end_flag = buffer(offset, 1):string()
    local end_flag_tree = subtree:add(f_end_flag, buffer(offset, 1))
    offset = offset + 1

    -- Field: flag
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field flag")
        dpi_error = true
        return
    end
    local flag = buffer(offset, 1):string()
    local flag_tree = subtree:add(f_flag, buffer(offset, 1))
    offset = offset + 1

    -- Field: id
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field id")
        dpi_error = true
        return
    end
    local id = buffer(offset, 4):uint()
    local id_tree = subtree:add(f_id, buffer(offset, 4))
    if id < 1045 or id > 9971 then
        id_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field id")
        dpi_error = true
    end
    offset = offset + 4

    -- Field: length
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field length")
        dpi_error = true
        return
    end
    local length = buffer(offset, 4):uint()
    local length_tree = subtree:add(f_length, buffer(offset, 4))
    if length < 6 or length > 13 then
        length_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field length")
        dpi_error = true
    end
    offset = offset + 4

    -- Field: message
    -- Dynamic array field: message (length defined by field 'length')
    local dynamic_length = length
    if dynamic_length < 6 or dynamic_length > 13 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Dynamic field message length (" .. dynamic_length .. ") out of allowed range")
        dpi_error = true
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for dynamic field message")
        dpi_error = true
        return
    end
    local message = buffer(offset, dynamic_length):string()
    local message_tree = subtree:add(f_message, buffer(offset, dynamic_length))
    offset = offset + dynamic_length

    if dpi_error then
        pinfo.cols.info:append(" [DPI Error]")
        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, "DPI Error in this packet")
    end
end

-- Register this dissector to a UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, aviv zli_192_168_4_50)
