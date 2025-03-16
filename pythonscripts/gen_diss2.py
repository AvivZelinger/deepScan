#!/usr/bin/env python3
"""
This script reads a DPI JSON file that describes the protocol fields for each IP
and generates:
  1. A Wireshark Lua dissector file per IP that decodes each field and runs DPI tests.
     - If no errors, the Info column shows the parsed field values.
     - If errors, the Info column only shows "[DPI Error: ...]".
  2. A general static dissector (saved as <protocol>.lua) that decodes fields according 
     to fixed sizes (no DPI tests), showing a summary of fields in the Info column.

If a field has a non-null bitfields_count, it is treated as a bitfield regardless of its field_type.
For bitfields:
  - In the per-IP dissectors, the code checks that the number of bits set equals bitfields_count.
  - In the global static dissector, the field is simply displayed as a binary string.

For non-bitfield types, we now support "float" (32-bit) and "double" (64-bit) types.
"""

import json
import os

# Path to the DPI JSON file (change as needed)
JSON_FILENAME = "/mnt/c/Users/aviv/Desktop/newProject/server/dpi_output.json"

# Directory to save the Lua files
OUTPUT_DIR = "/mnt/c/Users/aviv/Desktop/newProject/data"

# UDP port to register the dissectors (change if needed)
UDP_PORT = 10000

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Load the DPI specification
with open(JSON_FILENAME, "r") as f:
    dpi_spec = json.load(f)

protocol = dpi_spec.get("protocol", "CustomProtocol")
dpi_data = dpi_spec.get("dpi", {})

##########################################################################
# Helper function to generate the list of all fields
##########################################################################
def generate_field_list(fields):
    all_fields = []
    for field_name, info in fields.items():
        all_fields.append(f"f_{field_name}")
    return all_fields

##########################################################################
# 1. Generate per-IP Lua dissectors (with DPI tests)
##########################################################################
for ip, fields in dpi_data.items():
    ip_clean = ip.replace('.', '_')
    proto_name = f"{protocol}_{ip_clean}"
    filename = f"{protocol}_for_{ip_clean}.lua"
    filepath = os.path.join(OUTPUT_DIR, filename)
    
    with open(filepath, "w") as outfile:
        # Header
        outfile.write(f"-- Wireshark Lua dissector for {protocol} on IP {ip}\n")
        outfile.write("-- Generated automatically from DPI JSON.\n\n")
        
        # Proto definition
        outfile.write(f"local {proto_name} = Proto(\"{proto_name}\", \"{protocol} for IP {ip}\")\n\n")
        
        # Declare ProtoFields for each field
        for field_name, info in fields.items():
            # If bitfields_count is not null, treat this field as a bitfield.
            if info.get("bitfields_count") is not None:
                size = info["min_size"]
                if size == 1:
                    proto_field_type = "ProtoField.uint8"
                elif size == 2:
                    proto_field_type = "ProtoField.uint16"
                elif size == 4:
                    proto_field_type = "ProtoField.uint32"
                elif size == 8:
                    proto_field_type = "ProtoField.uint64"
                else:
                    proto_field_type = "ProtoField.uint32"
                base = ""
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()} (Bitfield)\"){base}\n")
            else:
                # Otherwise, use the declared type.
                if info["field_type"] == "bool":
                    proto_field_type = "ProtoField.uint8"
                    base = ", base.DEC"
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
                elif info["field_type"] == "int":
                    size = info["min_size"]
                    if size == 1:
                        proto_field_type = "ProtoField.uint8"
                    elif size == 2:
                        proto_field_type = "ProtoField.uint16"
                    elif size == 4:
                        proto_field_type = "ProtoField.uint32"
                    elif size == 8:
                        proto_field_type = "ProtoField.uint64"
                    else:
                        proto_field_type = "ProtoField.uint32"
                    base = ", base.DEC"
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
                elif info["field_type"] == "char":
                    proto_field_type = "ProtoField.string"
                    base = ""
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
                elif info["field_type"] == "float":
                    proto_field_type = "ProtoField.float"
                    base = ""
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()} (Float)\"){base}\n")
                elif info["field_type"] == "double":
                    proto_field_type = "ProtoField.double"
                    base = ""
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()} (Double)\"){base}\n")
                else:
                    proto_field_type = "ProtoField.string"
                    base = ""
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
        
        outfile.write("\n")
        # Register all fields
        all_fields = generate_field_list(fields)
        outfile.write(f"{proto_name}.fields = {{ {', '.join(all_fields)} }}\n\n")
        
        # Begin dissector function and add helper functions for bitfield processing
        outfile.write(f"function {proto_name}.dissector(buffer, pinfo, tree)\n")
        outfile.write("    if buffer:len() == 0 then return end\n")
        outfile.write(f"    pinfo.cols.protocol = \"{protocol}\"\n")
        outfile.write(f"    local subtree = tree:add({proto_name}, buffer(), \"{protocol} for IP {ip}\")\n")
        outfile.write("    local offset = 0\n")
        outfile.write("    local dpi_error = false\n")
        outfile.write("    local error_messages = {}\n")
        outfile.write("    local parsed_values = {}\n\n")
        
        # Helper functions for bitfield type
        outfile.write("    -- Helper function to count the number of bits set in a value\n")
        outfile.write("    local function popcount(x)\n")
        outfile.write("        local count = 0\n")
        outfile.write("        while x > 0 do\n")
        outfile.write("            count = count + (x % 2)\n")
        outfile.write("            x = math.floor(x / 2)\n")
        outfile.write("        end\n")
        outfile.write("        return count\n")
        outfile.write("    end\n\n")
        
        outfile.write("    -- Helper function to convert a number to a binary string of a given bit length\n")
        outfile.write("    local function to_binary_str(num, bits)\n")
        outfile.write("        local s = \"\"\n")
        outfile.write("        for i = bits - 1, 0, -1 do\n")
        outfile.write("            local bit_val = bit.rshift(num, i)\n")
        outfile.write("            s = s .. (bit.band(bit_val, 1) == 1 and \"1\" or \"0\")\n")
        outfile.write("        end\n")
        outfile.write("        return s\n")
        outfile.write("    end\n\n")
        
        # Parse each field
        for field_name, info in fields.items():
            outfile.write(f"    -- Field: {field_name}\n")
            if info.get("bitfields_count") is not None:
                # Process as bitfield
                outfile.write(f"    if buffer:len() < offset + {info['min_size']} then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        dpi_error = true\n")
                outfile.write(f"        table.insert(error_messages, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        return\n")
                outfile.write("    end\n")
                if info["min_size"] == 8:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()\n")
                else:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint()\n")
                outfile.write(f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))\n")
                outfile.write(f"    local num_bits = {info['min_size']} * 8\n")
                outfile.write(f"    local actual_bit_count = popcount({field_name})\n")
                outfile.write(f"    if actual_bit_count ~= {info['bitfields_count']} then\n")
                outfile.write(f"        {field_name}_item:add_expert_info(PI_MALFORMED, PI_ERROR, \"Bitfield {field_name} expected {info['bitfields_count']} bits set, got \" .. actual_bit_count)\n")
                outfile.write("        dpi_error = true\n")
                outfile.write(f"        table.insert(error_messages, \"Bitfield {field_name} expected {info['bitfields_count']} bits set, got \" .. actual_bit_count)\n")
                outfile.write("    end\n")
                outfile.write("    local binary_str = to_binary_str(" + field_name + ", num_bits)\n")
                outfile.write(f"    {field_name}_item:append_text(\" (\" .. binary_str .. \")\")\n")
                outfile.write(f"    parsed_values['{field_name}'] = binary_str\n")
                outfile.write(f"    offset = offset + {info['min_size']}\n\n")
            else:
                if not info["is_dynamic_array"]:
                    outfile.write(f"    if buffer:len() < offset + {info['min_size']} then\n")
                    outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                    outfile.write("        dpi_error = true\n")
                    outfile.write(f"        table.insert(error_messages, \"Not enough bytes for {field_name}\")\n")
                    outfile.write("        return\n")
                    outfile.write("    end\n")
                    
                    if info["field_type"] in ["int", "bool"]:
                        if info["min_size"] == 8:
                            outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()\n")
                        else:
                            outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint()\n")
                    elif info["field_type"] == "float":
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):float()\n")
                    elif info["field_type"] == "double":
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):double()\n")
                    else:
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):string()\n")
                    outfile.write(f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))\n")
                    outfile.write(f"    parsed_values['{field_name}'] = {field_name}\n")
                    
                    if info["field_type"] in ["int", "bool"] and info["min_value"] is not None and info["max_value"] is not None:
                        outfile.write("    do\n")
                        if info["field_type"] == "bool":
                            outfile.write("        local min_val = 0\n" if info["min_value"] is False else "        local min_val = 1\n")
                            outfile.write("        local max_val = 0\n" if info["max_value"] is False else "        local max_val = 1\n")
                            outfile.write(f"        if {field_name} < min_val or {field_name} > max_val then\n")
                        else:
                            outfile.write(f"        local min_val = {info['min_value']}\n")
                            outfile.write(f"        local max_val = {info['max_value']}\n")
                            outfile.write(f"        if {field_name} < min_val or {field_name} > max_val then\n")
                        outfile.write(f"            {field_name}_item:add_expert_info(PI_MALFORMED, PI_ERROR, \"Value out of range for {field_name}\")\n")
                        outfile.write("            dpi_error = true\n")
                        outfile.write(f"            table.insert(error_messages, \"{field_name} out of range\")\n")
                        outfile.write("        end\n")
                        outfile.write("    end\n")
                    
                    outfile.write(f"    offset = offset + {info['min_size']}\n\n")
                else:
                    # Dynamic array fields (for non-bitfield types)
                    size_field = info["size_defining_field"]
                    outfile.write(f"    local dynamic_length = {size_field}\n")
                    outfile.write(f"    if dynamic_length < {info['min_size']} or dynamic_length > {info['max_size']} then\n")
                    outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"{field_name} length out of range\")\n")
                    outfile.write("    end\n")
                    outfile.write(f"    if buffer:len() < offset + dynamic_length then\n")
                    outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                    outfile.write("        dpi_error = true\n")
                    outfile.write(f"        table.insert(error_messages, \"Not enough bytes for {field_name}\")\n")
                    outfile.write("        return\n")
                    outfile.write("    end\n")
                    
                    if info["field_type"] in ["int", "bool"]:
                        if info["min_size"] == 8:
                            outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):uint64()\n")
                        else:
                            outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):uint()\n")
                    elif info["field_type"] == "float":
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):float()\n")
                    elif info["field_type"] == "double":
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):double()\n")
                    else:
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):string()\n")
                    outfile.write(f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, dynamic_length))\n")
                    outfile.write(f"    parsed_values['{field_name}'] = {field_name}\n")
                    outfile.write("    offset = offset + dynamic_length\n\n")
        
        # Set Info column based on whether any DPI error was found
        outfile.write("    if dpi_error then\n")
        outfile.write("        local msg = table.concat(error_messages, \"; \")\n")
        outfile.write("        pinfo.cols.info = \"[DPI Error: \" .. msg .. \"]\"\n")
        outfile.write("        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, \"DPI Error in this packet\")\n")
        outfile.write("    else\n")
        outfile.write("        local parts = {}\n")
        outfile.write("        for k,v in pairs(parsed_values) do\n")
        outfile.write("            table.insert(parts, k .. \"=\" .. tostring(v))\n")
        outfile.write("        end\n")
        outfile.write("        table.sort(parts)\n")
        outfile.write("        pinfo.cols.info = table.concat(parts, \", \")\n")
        outfile.write("    end\n")
        
        outfile.write("end\n\n")
        
        outfile.write("-- Register this dissector for UDP port\n")
        outfile.write("local udp_port = DissectorTable.get(\"udp.port\")\n")
        outfile.write(f"udp_port:add({UDP_PORT}, {proto_name})\n")
    
    print(f"Generated per-IP dissector: {filepath}")

##########################################################################
# 2. Generate a static general dissector for ALL IPs (no DPI tests)
##########################################################################
if dpi_data:
    first_ip = next(iter(dpi_data))
    fields = dpi_data[first_ip]
    static_filename = f"{protocol}.lua"
    static_filepath = os.path.join(OUTPUT_DIR, static_filename)
    
    with open(static_filepath, "w") as outfile:
        outfile.write(f"-- Wireshark Lua static dissector for {protocol}\n")
        outfile.write("-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.\n\n")
        
        outfile.write(f"local {protocol} = Proto(\"{protocol}\", \"{protocol}\")\n\n")
        
        # Declare ProtoFields for the static dissector
        for field_name, info in fields.items():
            if info.get("bitfields_count") is not None:
                size = info["min_size"]
                if size == 1:
                    proto_field_type = "ProtoField.uint8"
                elif size == 2:
                    proto_field_type = "ProtoField.uint16"
                elif size == 4:
                    proto_field_type = "ProtoField.uint32"
                elif size == 8:
                    proto_field_type = "ProtoField.uint64"
                else:
                    proto_field_type = "ProtoField.uint32"
                base = ""
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()} (Bitfield)\"){base}\n")
            else:
                if info["field_type"] == "bool":
                    proto_field_type = "ProtoField.uint8"
                    base = ", base.DEC"
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
                elif info["field_type"] == "int":
                    size = info["min_size"]
                    if size == 1:
                        proto_field_type = "ProtoField.uint8"
                    elif size == 2:
                        proto_field_type = "ProtoField.uint16"
                    elif size == 4:
                        proto_field_type = "ProtoField.uint32"
                    elif size == 8:
                        proto_field_type = "ProtoField.uint64"
                    else:
                        proto_field_type = "ProtoField.uint32"
                    base = ", base.DEC"
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
                elif info["field_type"] == "char":
                    proto_field_type = "ProtoField.string"
                    base = ""
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
                elif info["field_type"] == "float":
                    proto_field_type = "ProtoField.float"
                    base = ""
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()} (Float)\"){base}\n")
                elif info["field_type"] == "double":
                    proto_field_type = "ProtoField.double"
                    base = ""
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()} (Double)\"){base}\n")
                else:
                    proto_field_type = "ProtoField.string"
                    base = ""
                    outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
        
        outfile.write("\n")
        all_fields = generate_field_list(fields)
        outfile.write(f"{protocol}.fields = {{ {', '.join(all_fields)} }}\n\n")
        
        outfile.write(f"function {protocol}.dissector(buffer, pinfo, tree)\n")
        outfile.write("    if buffer:len() == 0 then return end\n")
        outfile.write(f"    pinfo.cols.protocol = \"{protocol}\"\n")
        outfile.write(f"    local subtree = tree:add({protocol}, buffer(), \"{protocol}\")\n")
        outfile.write("    local offset = 0\n")
        outfile.write("    local field_values = {}\n\n")
        
        # Add helper functions for bitfield processing (ensure newline after comment)
        outfile.write("-- Add helper functions for bitfield processing\n")
        outfile.write("    local function popcount(x)\n")
        outfile.write("        local count = 0\n")
        outfile.write("        while x > 0 do\n")
        outfile.write("            count = count + (x % 2)\n")
        outfile.write("            x = math.floor(x / 2)\n")
        outfile.write("        end\n")
        outfile.write("        return count\n")
        outfile.write("    end\n\n")
        
        outfile.write("    local function to_binary_str(num, bits)\n")
        outfile.write("        local s = \"\"\n")
        outfile.write("        for i = bits - 1, 0, -1 do\n")
        outfile.write("            local bit_val = bit.rshift(num, i)\n")
        outfile.write("            s = s .. (bit.band(bit_val, 1) == 1 and \"1\" or \"0\")\n")
        outfile.write("        end\n")
        outfile.write("        return s\n")
        outfile.write("    end\n\n")
        
        for field_name, info in fields.items():
            outfile.write(f"    -- Field: {field_name}\n")
            if info.get("bitfields_count") is not None:
                outfile.write(f"    if buffer:len() < offset + {info['min_size']} then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        return\n")
                outfile.write("    end\n")
                if info["min_size"] == 8:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()\n")
                else:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint()\n")
                outfile.write(f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))\n")
                outfile.write(f"    local num_bits = {info['min_size']} * 8\n")
                outfile.write("    local binary_str = to_binary_str(" + field_name + ", num_bits)\n")
                outfile.write(f"    {field_name}_item:append_text(\" (\" .. binary_str .. \")\")\n")
                outfile.write(f"    field_values['{field_name}'] = binary_str\n")
                outfile.write(f"    offset = offset + {info['min_size']}\n\n")
            else:
                if not info["is_dynamic_array"]:
                    outfile.write(f"    if buffer:len() < offset + {info['min_size']} then\n")
                    outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                    outfile.write("        return\n")
                    outfile.write("    end\n")
                    if info["field_type"] in ["int", "bool"]:
                        if info["min_size"] == 8:
                            outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()\n")
                        else:
                            outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint()\n")
                    elif info["field_type"] == "float":
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):float()\n")
                    elif info["field_type"] == "double":
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):double()\n")
                    else:
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):string()\n")
                    outfile.write(f"    subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))\n")
                    outfile.write(f"    field_values['{field_name}'] = {field_name}\n")
                    outfile.write(f"    offset = offset + {info['min_size']}\n\n")
                else:
                    size_field = info["size_defining_field"]
                    outfile.write(f"    local dynamic_length = {size_field}\n")
                    outfile.write(f"    if dynamic_length < {info['min_size']} or dynamic_length > {info['max_size']} then\n")
                    outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"{field_name} length out of range\")\n")
                    outfile.write("    end\n")
                    outfile.write(f"    if buffer:len() < offset + dynamic_length then\n")
                    outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                    outfile.write("        return\n")
                    outfile.write("    end\n")
                    
                    if info["field_type"] in ["int", "bool"]:
                        if info["min_size"] == 8:
                            outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):uint64()\n")
                        else:
                            outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):uint()\n")
                    elif info["field_type"] == "float":
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):float()\n")
                    elif info["field_type"] == "double":
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):double()\n")
                    else:
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):string()\n")
                    outfile.write(f"    subtree:add(f_{field_name}, buffer(offset, dynamic_length))\n")
                    outfile.write(f"    field_values['{field_name}'] = {field_name}\n")
                    outfile.write("    offset = offset + dynamic_length\n\n")
        
        outfile.write("    local parts = {}\n")
        outfile.write("    for k,v in pairs(field_values) do\n")
        outfile.write("        table.insert(parts, k .. \"=\" .. tostring(v))\n")
        outfile.write("    end\n")
        outfile.write("    table.sort(parts)\n")
        outfile.write("    pinfo.cols.info = \"Static: \" .. table.concat(parts, \", \")\n")
        
        outfile.write("end\n\n")
        outfile.write("-- Register this dissector for the UDP port\n")
        outfile.write("local udp_port = DissectorTable.get(\"udp.port\")\n")
        outfile.write(f"udp_port:add({UDP_PORT}, {protocol})\n")
    
    print(f"Generated global static dissector: {static_filepath}")
