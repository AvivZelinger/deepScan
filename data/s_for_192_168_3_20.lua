-- Wireshark Lua dissector for s on IP 192.168.3.20
-- This file was generated automatically from the DPI JSON description.

local s_192_168_3_20 = Proto("s_192_168_3_20", "s for IP 192.168.3.20")

local f_start_flag = ProtoField.uint8("s_192_168_3_20.start_flag", "Start_flag"), base.DEC
local f_msg_id = ProtoField.uint32("s_192_168_3_20.msg_id", "Msg_id"), base.DEC
local f_command = ProtoField.string("s_192_168_3_20.command", "Command")
local f_data_length = ProtoField.uint16("s_192_168_3_20.data_length", "Data_length"), base.DEC
local f_data = ProtoField.string("s_192_168_3_20.data", "Data")
local f_end_flag = ProtoField.uint8("s_192_168_3_20.end_flag", "End_flag"), base.DEC

s_192_168_3_20.fields = { f_start_flag, f_msg_id, f_command, f_data_length, f_data, f_end_flag }

function s_192_168_3_20.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "s (192.168.3.20)"
    local subtree = tree:add(s_192_168_3_20, buffer(), "s for IP 192.168.3.20")
    local offset = 0
    local dpi_error = false  -- flag to indicate any DPI test failure

    -- Field: start_flag
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field start_flag")
        dpi_error = true
        return
    end
    local start_flag = buffer(offset, 1):uint()
    local start_flag_tree = subtree:add(f_start_flag, buffer(offset, 1))
    if start_flag < 0 or start_flag > 1 then
        start_flag_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field start_flag")
        dpi_error = true
    end
    offset = offset + 1

    -- Field: msg_id
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field msg_id")
        dpi_error = true
        return
    end
    local msg_id = buffer(offset, 4):uint()
    local msg_id_tree = subtree:add(f_msg_id, buffer(offset, 4))
    if msg_id < 1807 or msg_id > 9961 then
        msg_id_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field msg_id")
        dpi_error = true
    end
    offset = offset + 4

    -- Field: command
    if buffer:len() < offset + 8 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field command")
        dpi_error = true
        return
    end
    local command = buffer(offset, 8):string()
    local command_tree = subtree:add(f_command, buffer(offset, 8))
    offset = offset + 8

    -- Field: data_length
    if buffer:len() < offset + 2 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field data_length")
        dpi_error = true
        return
    end
    local data_length = buffer(offset, 2):uint()
    local data_length_tree = subtree:add(f_data_length, buffer(offset, 2))
    if data_length < 0 or data_length > 19 then
        data_length_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field data_length")
        dpi_error = true
    end
    offset = offset + 2

    -- Field: data
    -- Dynamic array field: data (length defined by field 'data_length')
    local dynamic_length = data_length
    if dynamic_length < 0 or dynamic_length > 19 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Dynamic field data length (" .. dynamic_length .. ") out of allowed range")
        dpi_error = true
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for dynamic field data")
        dpi_error = true
        return
    end
    local data = buffer(offset, dynamic_length):string()
    local data_tree = subtree:add(f_data, buffer(offset, dynamic_length))
    offset = offset + dynamic_length

    -- Field: end_flag
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field end_flag")
        dpi_error = true
        return
    end
    local end_flag = buffer(offset, 1):uint()
    local end_flag_tree = subtree:add(f_end_flag, buffer(offset, 1))
    if end_flag < 0 or end_flag > 1 then
        end_flag_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field end_flag")
        dpi_error = true
    end
    offset = offset + 1

    if dpi_error then
        pinfo.cols.info:append(" [DPI Error]")
        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, "DPI Error in this packet")
    end
end

-- Register this dissector to a UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, s_192_168_3_20)
