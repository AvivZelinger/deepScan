#include "modulestuct.h"

// Note: field_val has been removed from the code

modulestruct* setup_modulestruct(int amountoffields, int *field_sizes, char **field_names, char **field_types, char **size_field_names) {
    modulestruct* module = (modulestruct*)malloc(amountoffields * sizeof(modulestruct));

    for (int i = 0; i < amountoffields; i++) {
        module[i].field_name = field_names[i];
        module[i].field_size = field_sizes[i];
        module[i].field_type = field_types[i];
        // If the provided size_field_names string is empty, set to NULL
        if (size_field_names[i] != NULL && strlen(size_field_names[i]) > 0) {
            module[i].size_field_name = size_field_names[i];
        } else {
            module[i].size_field_name = NULL;
        }
    }
    return module;
}

void print_modulestruct(modulestruct *module, int amountoffields) {
    for (int i = 0; i < amountoffields; i++) {
        printf("Field %d\n", i);
        printf("    Name         : %s\n",   module[i].field_name);
        printf("    Size         : %d\n",   module[i].field_size);
        printf("    Type         : %s\n",   module[i].field_type);
        printf("    Size Field   : %s\n\n", (module[i].size_field_name) ? module[i].size_field_name : "NULL");
    }
}

void user_input() {
    int amountoffields;
    printf("Enter the amount of fields: ");
    scanf("%d", &amountoffields);

    // Allocate memory for field sizes, names, types, and size field names
    int   *field_sizes       = (int*)malloc(amountoffields * sizeof(int));
    char **field_names       = (char**)malloc(amountoffields * sizeof(char*));
    char **field_types       = (char**)malloc(amountoffields * sizeof(char*));
    char **size_field_names  = (char**)malloc(amountoffields * sizeof(char*));

    for (int i = 0; i < amountoffields; i++) {
        printf("Enter the size of field %d: ", i);
        scanf("%d", &field_sizes[i]);

        field_names[i] = (char*)malloc(50 * sizeof(char));
        printf("Enter the name of field %d: ", i);
        scanf("%49s", field_names[i]);

        field_types[i] = (char*)malloc(50 * sizeof(char));
        printf("Enter the type of field %d (e.g., int, float, char): ", i);
        scanf("%49s", field_types[i]);

        size_field_names[i] = (char*)malloc(50 * sizeof(char));
        printf("Enter the name of the field that indicates the size for field %d (or press enter if none): ", i);
        // Read entire line to allow empty input. Use fgets after consuming newline.
        getchar();  // consume newline left by scanf
        fgets(size_field_names[i], 50, stdin);
        // Remove trailing newline if present
        size_field_names[i][strcspn(size_field_names[i], "\n")] = '\0';
        // If the input is empty, set pointer to NULL (free the allocated memory)
        if (strlen(size_field_names[i]) == 0) {
            free(size_field_names[i]);
            size_field_names[i] = NULL;
        }
    }

    // Set up and print the module structure
    modulestruct *module = setup_modulestruct(amountoffields, field_sizes, field_names, field_types, size_field_names);
    print_modulestruct(module, amountoffields);

    // Free allocated memory
    for (int i = 0; i < amountoffields; i++) {
        free(field_names[i]);
        free(field_types[i]);
        if (size_field_names[i])
            free(size_field_names[i]);
    }
    free(field_names);
    free(field_types);
    free(size_field_names);
    free(field_sizes);
    free(module);
}

void generate_wireshark_dissector(modulestruct *module, int amountoffields, const char* protocol_name, int udp_port) {
    // (Unchanged except that we no longer refer to field_val)
    char* filename = malloc(strlen(protocol_name) + 20);
    sprintf(filename, "%s_dissector.lua", protocol_name);
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        printf("Error: Could not open file for writing\n");
        free(filename);
        return;
    }

    fprintf(file, "-- Wireshark Lua dissector for %s protocol running over UDP (Layer 5)\n", protocol_name);
    fprintf(file, "local %s_proto = Proto(\"%s\", \"%s Layer 5 Protocol\")\n\n", protocol_name, protocol_name, protocol_name);

    fprintf(file, "-- Protocol fields\n");
    for (int i = 0; i < amountoffields; i++) {
        if (strcmp(module[i].field_type, "int") == 0) {
            fprintf(file, "local f_%s = ProtoField.uint%d(\"%s.%s\", \"%s\", base.DEC)\n",
                    module[i].field_name, 
                    module[i].field_size * 8,
                    protocol_name, 
                    module[i].field_name, 
                    module[i].field_name);
        }
        else if (strcmp(module[i].field_type, "float") == 0) {
            fprintf(file, "local f_%s = ProtoField.float(\"%s.%s\", \"%s\")\n",
                    module[i].field_name, 
                    protocol_name,
                    module[i].field_name,
                    module[i].field_name);
        }
        else if (strcmp(module[i].field_type, "char") == 0) {
            fprintf(file, "local f_%s = ProtoField.string(\"%s.%s\", \"%s\")\n",
                    module[i].field_name, 
                    protocol_name,
                    module[i].field_name,
                    module[i].field_name);
        }
        else {
            fprintf(file, "local f_%s = ProtoField.bytes(\"%s.%s\", \"%s\")\n",
                    module[i].field_name, 
                    protocol_name,
                    module[i].field_name,
                    module[i].field_name);
        }
    }

    fprintf(file, "\n%s_proto.fields = {", protocol_name);
    for (int i = 0; i < amountoffields; i++) {
        fprintf(file, "f_%s", module[i].field_name);
        if (i != amountoffields - 1) fprintf(file, ", ");
    }
    fprintf(file, "}\n\n");

    fprintf(file, "-- Dissector function\n");
    fprintf(file, "function %s_proto.dissector(buffer, pinfo, tree)\n", protocol_name);
    fprintf(file, "    pinfo.cols.protocol = \"%s\"\n", protocol_name);
    fprintf(file, "    local subtree = tree:add(%s_proto, buffer(), \"%s Layer 5 Protocol Data\")\n\n", protocol_name, protocol_name);

    int offset = 0;
    for (int i = 0; i < amountoffields; i++) {
        fprintf(file, "    subtree:add(f_%s, buffer(%d, %d))\n", 
                module[i].field_name, 
                offset, 
                module[i].field_size);
        offset += module[i].field_size;
    }

    fprintf(file, "end\n\n");

    fprintf(file, "-- Register the dissector to the specified UDP port\n");
    fprintf(file, "local udp_port_table = DissectorTable.get(\"udp.port\")\n");
    fprintf(file, "udp_port_table:add(%d, %s_proto)\n", udp_port, protocol_name);

    fclose(file);
    free(filename);

    printf("Wireshark Lua dissector generated successfully in %s_dissector.lua\n", protocol_name);
}

// The UDP sending functions remain unchanged here. They originally used field_val,
// so you may need to update them if you wish to send actual values.

void create_table_in_db(modulestruct *module, int amount_of_fields) {
    MYSQL *conn;
    char query[2048];

    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
        exit(EXIT_FAILURE);
    }

    if (mysql_real_connect(conn, "localhost", "root", "admin", "project", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    // Create table with extra column for the size indicator (named fieldname_size_field)
    snprintf(query, sizeof(query), 
             "CREATE TABLE IF NOT EXISTS MyTable (id INT AUTO_INCREMENT PRIMARY KEY");
    for (int i = 0; i < amount_of_fields; i++) {
        snprintf(query + strlen(query), sizeof(query) - strlen(query),
                 ", %s VARCHAR(50), %s_type VARCHAR(20), %s_size_field VARCHAR(50)",
                 module[i].field_name,
                 module[i].field_name,
                 module[i].field_name);
    }
    strcat(query, ");");

    printf("\n%s\n\n", query);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "CREATE TABLE failed. Error: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    printf("Table created successfully.\n");
    mysql_close(conn);
}

void escape_single_quotes(const char *input, char *output, size_t max_len) {
    size_t i = 0, j = 0;
    while (input[i] != '\0' && j < max_len - 1) {
        if (input[i] == '\'') {
            if (j + 2 >= max_len - 1) break;
            output[j++] = '\\';
        }
        output[j++] = input[i++];
    }
    output[j] = '\0';
}

void insert_values_into_db(modulestruct *module, int amount_of_fields) {
    MYSQL *conn;
    char query[2048];

    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
        exit(EXIT_FAILURE);
    }

    if (mysql_real_connect(conn, "localhost", "root", "admin", "project", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    // Build the INSERT query including the size field indicator column.
    snprintf(query, sizeof(query), "INSERT INTO MyTable (");
    for (int i = 0; i < amount_of_fields; i++) {
        snprintf(query + strlen(query), sizeof(query) - strlen(query),
                 "%s%s, %s_type, %s_size_field",
                 (i == 0) ? "" : ", ",
                 module[i].field_name,
                 module[i].field_name,
                 module[i].field_name);
    }
    strcat(query, ") VALUES (");
    for (int i = 0; i < amount_of_fields; i++) {
        // For this example, we'll insert dummy values for the field value (empty string)
        // since there is no field_val anymore.
        // The size field indicator is inserted as either its name or NULL.
        snprintf(query + strlen(query), sizeof(query) - strlen(query),
                 "%s'%s', '%s', %s",
                 (i == 0) ? "" : ", ",
                 "",  // Dummy value for field value
                 module[i].field_type,
                 (module[i].size_field_name) ? 
                    (sprintf(query + strlen(query), "'%s'", module[i].size_field_name), query + strlen(query) - strlen(module[i].size_field_name) - 2) : "NULL");
        // Note: The above inline sprintf trick is used to insert the string.
        // Alternatively, you can build the query in separate steps.
    }
    strcat(query, ");");

    printf("\n%s\n\n", query);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "INSERT INTO failed. Error: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    printf("Values inserted successfully.\n");
    mysql_close(conn);
}

void create_and_insert_table_with_sizes(modulestruct *module, int amount_of_fields) {
    MYSQL *conn;
    char query[4096];
    printf("Creating ProtocolSizesAndType table with auto numbering for fields...\n");

    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
        exit(EXIT_FAILURE);
    }

    if (mysql_real_connect(conn, "localhost", "root", "admin", "project", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed. Error: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    // שינוי: הוספת עמודת id עם AUTO_INCREMENT כמפתח ראשי
    snprintf(query, sizeof(query),
             "CREATE TABLE IF NOT EXISTS ProtocolSizesAndType ("
             "id INT NOT NULL AUTO_INCREMENT, "
             "name VARCHAR(50), "
             "size INT, "
             "type VARCHAR(20), "
             "size_field VARCHAR(50), "
             "PRIMARY KEY (id)"
             ");");

    printf("\nExecuting Query:\n%s\n\n", query);
    if (mysql_query(conn, query)) {
        fprintf(stderr, "CREATE TABLE ProtocolSizesAndType failed. Error: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    // מכיוון שעכשיו העמודה הראשית היא id, לא נכניס ערך לעמודה זו.
    const char *insert_query_template = "INSERT INTO ProtocolSizesAndType (name, size, type, size_field) VALUES ('%s', %d, '%s', %s);";

    for (int i = 0; i < amount_of_fields; i++) {
        char escaped_name[100];
        char escaped_type[100];
        escape_single_quotes(module[i].field_name, escaped_name, sizeof(escaped_name));
        escape_single_quotes(module[i].field_type, escaped_type, sizeof(escaped_type));

        // טיפול בערך של size_field_name – אם NULL, מעבירים SQL NULL, אחרת מצרפים את המחרוזת בגרשיים.
        char *size_field_value = (module[i].size_field_name) ? module[i].size_field_name : NULL;
        char size_field_sql[100];
        if (size_field_value) {
            snprintf(size_field_sql, sizeof(size_field_sql), "'%s'", size_field_value);
        } else {
            strcpy(size_field_sql, "NULL");
        }

        snprintf(query, sizeof(query), insert_query_template, escaped_name, module[i].field_size, escaped_type, size_field_sql);

        printf("\nExecuting Query (Insert Field %d):\n%s\n\n", i + 1, query);
        if (mysql_query(conn, query)) {
            if (mysql_errno(conn) == 1062) {
                printf("Duplicate entry for field '%s'. Skipping insertion.\n", module[i].field_name);
                continue;
            } else {
                fprintf(stderr, "INSERT into ProtocolSizesAndType failed. Error: %s\n", mysql_error(conn));
                mysql_close(conn);
                exit(EXIT_FAILURE);
            }
        }
    }

    printf("ProtocolSizesAndType table created and inserted successfully.\n");
    mysql_close(conn);
}


// void randomize_and_send_udp_multiple(modulestruct *module, int amount_of_fields, int *min_values, int *max_values, const char *ip, int port, int number_of_times) {
//     // This function originally randomized field_val.
//     // Since field_val no longer exists, you may need to modify the behavior.
//     // For now, we simply print the field information and simulate sending.
//     srand(time(NULL));
//     for (int j = 0; j < number_of_times; j++) {
//         printf("Sending packet %d:\n", j + 1);
//         for (int i = 0; i < amount_of_fields; i++) {
//             // Instead of randomizing a field value, we simply print the field details.
//             printf("Field %d: %s, Size: %d, Type: %s, Size Field: %s\n", 
//                    i, 
//                    module[i].field_name, 
//                    module[i].field_size, 
//                    module[i].field_type, 
//                    (module[i].size_field_name) ? module[i].size_field_name : "NULL");
//         }
//         // Call UDP send functions if needed.
//         send_modulestruct_udp(module, amount_of_fields, ip, port);
//     }
// }

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    const struct iphdr *ip_header = (struct iphdr *)(packet + 14);
    int ip_header_len = ip_header->ihl * 4;

    if (ip_header->protocol == IPPROTO_UDP) {
        const struct udphdr *udp_header = (struct udphdr *)((unsigned char *)ip_header + ip_header_len);
        int udp_header_len = sizeof(struct udphdr);
        if (ntohs(udp_header->uh_dport) == 8383) {
            const unsigned char *payload = (unsigned char *)udp_header + udp_header_len;
            int payload_len = ntohs(udp_header->uh_ulen) - udp_header_len;
            for (int i = 0; i < payload_len; i++) {
                printf("%02x ", payload[i]);
            }
            printf("\n");
        }
    }
}

void pcapreader() {
    char *pcap_file = "testing.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening file: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_loop(handle, -1, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error processing packets: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_close(handle);
}

modulestruct* build_structure_from_file(const char *filename, int *amountoffields) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    // Read the first line to get the number of fields.
    if (fscanf(file, "%d", amountoffields) != 1) {
        fprintf(stderr, "Error reading the number of fields\n");
        fclose(file);
        return NULL;
    }
    // Consume the rest of the line.
    char dummy[256];
    fgets(dummy, sizeof(dummy), file);

    // Allocate memory for modulestruct array.
    modulestruct* module = (modulestruct*)malloc(*amountoffields * sizeof(modulestruct));
    if (!module) {
        perror("malloc failed");
        fclose(file);
        return NULL;
    }

    char line[256];
    int index = 0;
    while (index < *amountoffields && fgets(line, sizeof(line), file)) {
        // Trim the newline if present.
        line[strcspn(line, "\n")] = '\0';

        char field_name[50];
        int field_size;
        char field_type[50];
        char size_field[50] = "";

        // Try to read 4 tokens (if the size field indicator is provided)
        int tokens = sscanf(line, "%49s %d %49s %49s", field_name, &field_size, field_type, size_field);
        if (tokens < 3) {
            fprintf(stderr, "Error parsing line: %s\n", line);
            continue;
        }
        // Copy the parsed values into the struct.
        module[index].field_name = strdup(field_name);
        module[index].field_size = field_size;
        module[index].field_type = strdup(field_type);
        if (tokens == 4 && strlen(size_field) > 0) {
            module[index].size_field_name = strdup(size_field);
        } else {
            module[index].size_field_name = NULL;
        }
        index++;
    }

    fclose(file);
    return module;
}


void generate_wireshark_dissector2(modulestruct *module, int amountoffields, const char* protocol_name, int udp_port) {
    char* filename = malloc(strlen(protocol_name) + 20);
    sprintf(filename, "%s_dissector.lua", protocol_name);
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        printf("Error: Could not open file for writing\n");
        free(filename);
        return;
    }

    fprintf(file, "-- Wireshark Lua dissector for %s protocol running over UDP (Layer 5)\n", protocol_name);
    fprintf(file, "local %s_proto = Proto(\"%s\", \"%s Layer 5 Protocol\")\n\n", protocol_name, protocol_name, protocol_name);

    fprintf(file, "-- Protocol fields\n");
    for (int i = 0; i < amountoffields; i++) {
        if (module[i].field_size == 0) {
            fprintf(file, "local f_%s = ProtoField.bytes(\"%s.%s\", \"%s (dynamic size)\")\n",
                    module[i].field_name,
                    protocol_name,
                    module[i].field_name,
                    module[i].field_name);
        } else if (strcmp(module[i].field_type, "int") == 0) {
            fprintf(file, "local f_%s = ProtoField.uint%d(\"%s.%s\", \"%s\", base.DEC)\n",
                    module[i].field_name, 
                    module[i].field_size * 8,
                    protocol_name, 
                    module[i].field_name, 
                    module[i].field_name);
        } else if (strcmp(module[i].field_type, "float") == 0) {
            fprintf(file, "local f_%s = ProtoField.float(\"%s.%s\", \"%s\")\n",
                    module[i].field_name, 
                    protocol_name,
                    module[i].field_name,
                    module[i].field_name);
        } else if (strcmp(module[i].field_type, "char") == 0) {
            fprintf(file, "local f_%s = ProtoField.string(\"%s.%s\", \"%s\")\n",
                    module[i].field_name, 
                    protocol_name,
                    module[i].field_name,
                    module[i].field_name);
        } else {
            fprintf(file, "local f_%s = ProtoField.bytes(\"%s.%s\", \"%s\")\n",
                    module[i].field_name, 
                    protocol_name,
                    module[i].field_name,
                    module[i].field_name);
        }
    }

    fprintf(file, "\n%s_proto.fields = {", protocol_name);
    for (int i = 0; i < amountoffields; i++) {
        fprintf(file, "f_%s", module[i].field_name);
        if (i != amountoffields - 1) fprintf(file, ", ");
    }
    fprintf(file, "}\n\n");

    fprintf(file, "-- Dissector function\n");
    fprintf(file, "function %s_proto.dissector(buffer, pinfo, tree)\n", protocol_name);
    fprintf(file, "    pinfo.cols.protocol = \"%s\"\n", protocol_name);
    fprintf(file, "    local subtree = tree:add(%s_proto, buffer(), \"%s Layer 5 Protocol Data\")\n\n", protocol_name, protocol_name);

    int offset = 0;
    for (int i = 0; i < amountoffields; i++) {
        if (module[i].field_size == 0) {
            if (i == amountoffields - 1) {
                fprintf(file, "    local dynamic_field_size = buffer:len() - %d\n", offset);
                fprintf(file, "    subtree:add(f_%s, buffer(%d, dynamic_field_size))\n", module[i].field_name, offset);
            } else {
                fprintf(file, "    -- Dynamic field '%s' requires custom size logic\n", module[i].field_name);
                fprintf(file, "    local dynamic_field_size = buffer:len() - %d\n", offset);
                fprintf(file, "    subtree:add(f_%s, buffer(%d, dynamic_field_size))\n", module[i].field_name, offset);
            }
        } else {
            fprintf(file, "    subtree:add(f_%s, buffer(%d, %d))\n", module[i].field_name, offset, module[i].field_size);
            offset += module[i].field_size;
        }
    }

    fprintf(file, "end\n\n");
    fprintf(file, "-- Register the dissector to the specified UDP port\n");
    fprintf(file, "local udp_port_table = DissectorTable.get(\"udp.port\")\n");
    fprintf(file, "udp_port_table:add(%d, %s_proto)\n", udp_port, protocol_name);

    fclose(file);
    free(filename);

    printf("Wireshark Lua dissector with dynamic size handling generated successfully in %s_dissector.lua\n", protocol_name);
}

void clearSqlTable() {
    MYSQL *conn;
    char query[1024];

    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
        exit(EXIT_FAILURE);
    }

    if (mysql_real_connect(conn, "localhost", "root", "admin", "project", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    snprintf(query, sizeof(query), "DELETE FROM ProtocolSizesAndType");
    printf("\n%s\n\n", query);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "Delete TABLE failed. Error: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    printf("Table cleared successfully.\n");
    mysql_close(conn);
}

void clearUploadsFolder() {
    char *command = "rm -rf /mnt/c/Users/aviv/Desktop/newProject/server/uploads/*";
    system(command);
    printf("Uploads folder cleared successfully.\n");
}

// Compile example:
//   gcc -o modulestruct modulestruct.c -lpcap -lmysqlclient
//   (Adjust paths and libraries as needed)
//
// MySQL quick reference:
//   sudo mysql -u root -p   (password: admin)
//
// Example usage when linking:
//   gcc -o main runtest.c modulestruct.c -lpcap -lmysqlclient
