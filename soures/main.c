#include "../headers/modulestuct.h"

int main(int argc, char *argv[]) {
    // Check if the input file is provided
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filename = argv[1];
    int amountoffields;
    
    // Build the modulestruct from the input file
    modulestruct *module = build_structure_from_file(filename, &amountoffields);
    if (module == NULL) {
        fprintf(stderr, "Failed to build modulestruct from file.\n");
        return EXIT_FAILURE;
    }

    // Print the modulestruct
    printf("Modulestruct built from file:\n");
    print_modulestruct(module, amountoffields);

    // ----------------------------
    // Generate Wireshark Dissector
    // ----------------------------
    
    // char protocol_name[] = "my_protocol";
    // int udp_port= 10000;

    // generate_wireshark_dissector(module, amountoffields, protocol_name, udp_port);

    // --------------------
    // Database Operations
    // --------------------

    create_and_insert_table_with_sizes(module, amountoffields);
    }

