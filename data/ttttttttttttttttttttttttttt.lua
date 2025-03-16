-- Wireshark Lua static dissector for ttttttttttttttttttttttttttt
-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.

local ttttttttttttttttttttttttttt = Proto("ttttttttttttttttttttttttttt", "ttttttttttttttttttttttttttt")

local f_a = ProtoField.uint32("ttttttttttttttttttttttttttt.a", "A"), base.DEC

ttttttttttttttttttttttttttt.fields = { f_a }

function ttttttttttttttttttttttttttt.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "ttttttttttttttttttttttttttt"
    local subtree = tree:add(ttttttttttttttttttttttttttt, buffer(), "ttttttttttttttttttttttttttt")
    local offset = 0
    local field_values = {}

    -- Field: a
    local a = buffer(offset, 4):uint()
    subtree:add(f_a, buffer(offset, 4))
    field_values['a'] = a
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
udp_port:add(10000, ttttttttttttttttttttttttttt)
