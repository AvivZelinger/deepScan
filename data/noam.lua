-- Wireshark Lua static dissector for noam
-- This dissector decodes fields according to fixed sizes without DPI tests.

local noam = Proto("noam", "noam")

local f_start_flag = ProtoField.uint8("noam.start_flag", "Start_flag"), base.DEC
local f_msg_id = ProtoField.uint32("noam.msg_id", "Msg_id"), base.DEC
local f_command = ProtoField.string("noam.command", "Command")
local f_data_length = ProtoField.uint16("noam.data_length", "Data_length"), base.DEC
local f_data = ProtoField.string("noam.data", "Data")
local f_end_flag = ProtoField.uint8("noam.end_flag", "End_flag"), base.DEC

noam.fields = { f_start_flag, f_msg_id, f_command, f_data_length, f_data, f_end_flag }

function noam.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "noam"
    local subtree = tree:add(noam, buffer(), "noam")
    local offset = 0

    -- Field: start_flag
    local start_flag = buffer(offset, 1):uint()
    subtree:add(f_start_flag, buffer(offset, 1))
    offset = offset + 1

    -- Field: msg_id
    local msg_id = buffer(offset, 4):uint()
    subtree:add(f_msg_id, buffer(offset, 4))
    offset = offset + 4

    -- Field: command
    local command = buffer(offset, 8):string()
    subtree:add(f_command, buffer(offset, 8))
    offset = offset + 8

    -- Field: data_length
    local data_length = buffer(offset, 2):uint()
    subtree:add(f_data_length, buffer(offset, 2))
    offset = offset + 2

    -- Field: data
    -- Dynamic array field: data (length defined by field 'data_length')
    local dynamic_length = data_length
    local data = buffer(offset, dynamic_length):string()
    subtree:add(f_data, buffer(offset, dynamic_length))
    offset = offset + dynamic_length

    -- Field: end_flag
    local end_flag = buffer(offset, 1):uint()
    subtree:add(f_end_flag, buffer(offset, 1))
    offset = offset + 1

end

-- Register this dissector to a UDP port (change 10000 to the appropriate port as needed)
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, noam)
