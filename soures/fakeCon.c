#include "../headers/modulestuct.h"

int main()
{
    int amount_of_fields = 6;
    int min_values[] = {0, 0,'A', 0, 0, 'a'};
    int max_values[] = {65535, 15,'Z'*10,4 , 64, 'z'*5};
    const char *ip = "10.0.0.2";
    int port = 10000;
    int number_of_times = 1000;
    modulestruct module[6] = {
        {"test", 2, 0, "int"},
     {"type", 1, 0, "char"},
         {"msg", 10, 0, "string"},
      {"sec", 0, 0, "int"},
       {"arr", 5, 0, "char"}, 
       {"Darr", 5, 0, "char"}};
    create_and_insert_table_with_sizes(module, amount_of_fields);
    randomize_and_send_udp_multiple(module, amount_of_fields, min_values, max_values, ip, port, number_of_times);
    return 0;
}