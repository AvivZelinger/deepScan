-- Wireshark Lua static dissector for test
-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.

local test = Proto("test", "test")

local f_down = ProtoField.string("test.down", "Down")
local f_up = ProtoField.string("test.up", "Up")

test.fields = { f_down, f_up }

function test.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "test"
    local subtree = tree:add(test, buffer(), "test")
    local offset = 0
    local field_values = {}

    -- Field: down
    local down = buffer(offset, 4):string()
    subtree:add(f_down, buffer(offset, 4))
    field_values['down'] = down
    offset = offset + 4

    -- Field: up
    local up = buffer(offset, 4):string()
    subtree:add(f_up, buffer(offset, 4))
    field_values['up'] = up
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
udp_port:add(10000, test)
