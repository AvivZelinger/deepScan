#ifndef MODULESTRUCT_H
#define MODULESTRUCT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <limits.h>

// Updated structure: removed field_val and added size_field_name
typedef struct {
    char *field_name;
    int field_size;
    char *field_type;
    char *size_field_name; // Name of the field that indicates the size (or NULL)
} modulestruct;

// Function declarations
modulestruct* setup_modulestruct(int amountoffields, int *field_sizes, char **field_names, char **field_types, char **size_field_names);
void print_modulestruct(modulestruct *module, int amountoffields);
void user_input();
void generate_wireshark_dissector(modulestruct *module, int amountoffields, const char* protocol_name, int udp_port);
// Note: UDP sending functions have been left unchanged, but they referenced field_val.
// If you plan to send data, you will need to update them accordingly.
void send_modulestruct_udp(modulestruct *module, int amountoffields, const char *ip, int port);
void send_modulestruct_udp2(modulestruct *module, int amountoffields, const char *ip, int port);
void create_table_in_db(modulestruct *module, int amount_of_fields);
void insert_values_into_db(modulestruct *module, int amount_of_fields);
void create_and_insert_table_with_sizes(modulestruct *module, int amount_of_fields);
void randomize_and_send_udp_multiple(modulestruct *module, int amount_of_fields, int *min_values, int *max_values, const char *ip, int port, int number_of_times);
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void pcapreader();
modulestruct* build_structure_from_file(const char *filename, int *amountoffields);
void generate_wireshark_dissector2(modulestruct *module, int amountoffields, const char* protocol_name, int udp_port);
void clearSqlTable();
void clearUploadsFolder();

#endif // MODULESTRUCT_H
