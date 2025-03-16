#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <dirent.h>
#include <string.h>

void combine_pcapng_files(const char *output_file, const char *input_folder) {
    pcap_t *pcap;
    pcap_dumper_t *dumper;
    char errbuf[PCAP_ERRBUF_SIZE];
    dumper = NULL;

    DIR *dir = opendir(input_folder);
    if (!dir) {
        perror("Error opening directory");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) { // Check if it is a regular file
            char input_file[1024];
            snprintf(input_file, sizeof(input_file), "%s/%s", input_folder, entry->d_name);

            // Open each input file
            pcap = pcap_open_offline(input_file, errbuf);
            if (pcap == NULL) {
                fprintf(stderr, "Error opening file %s: %s\n", input_file, errbuf);
                continue;
            }

            if (dumper == NULL) {
                // Create the output file using the first file's link-layer header type
                dumper = pcap_dump_open(pcap, output_file);
                if (dumper == NULL) {
                    fprintf(stderr, "Error creating output file %s: %s\n", output_file, pcap_geterr(pcap));
                    pcap_close(pcap);
                    closedir(dir);
                    return;
                }
            }

            struct pcap_pkthdr *header;
            const u_char *data;

            // Read packets from the input file and write them to the output file
            while (pcap_next_ex(pcap, &header, &data) == 1) {
                pcap_dump((u_char *)dumper, header, data);
            }

            // Close the current input file
            pcap_close(pcap);
        }
    }

    closedir(dir);

    if (dumper != NULL) {
        pcap_dump_close(dumper);
    }

    printf("PCAPNG files combined successfully into %s\n", output_file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s output_file input_folder\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *output_file = argv[1];
    const char *input_folder = argv[2];

    combine_pcapng_files(output_file, input_folder);

    return EXIT_SUCCESS;
}
