#include <arpa/inet.h>// For inet_ntoa
#include <linux/sctp.h>
#include <net/ethernet.h>// For ether_header and ETHERTYPE_XXX (on Linux)
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <getopt.h>

#include <iostream>
#include <string>

#include <cstdio>
#include <cstring>
#include <ctime>

#include <pcap.h>

// #include "Session.h"
// #include "SessionCollection.h"

#define PROGRAM_NAME "packet-inspector"

#define AUTHOR "TheSudoer"

#ifdef BE_VERBOSE
#define VERBOSE(x) x
#else
#define VERBOSE(x)
#endif

#ifdef DO_DEBUGGING
#define DEBUG(x) x
#else
#define DEBUG(x)
#endif

inline void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) noexcept;
inline void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) noexcept;

const char *short_opts = "hi::r:";
const struct option long_opts[] =
{
    { "help", no_argument, nullptr, 'h' },
    { "interface", optional_argument, nullptr, 'i' },
    { "read", required_argument, nullptr, 'r' },
    { nullptr, 0, nullptr, 0 }
};

void usage(int status) noexcept
{
    std::cout << "Usage:\n"
              << std::format("\t{} [OPTIONS]\n", PROGRAM_NAME) << "Options:\n"
              << "  -i, --interface [IFACE]   Listen on given interface (don't write IFACE for using default)\n"
              << "  -r, --read <PCAP>         Read packets from a pcap file\n"
              << "  -h, --help                Show this help message\n"
              << "\nNote: -i and -r are mutually exclusive.\n";

    exit(status);
}

// ProgramOptions parse_arguments(int argc, char *argv[]) noexcept
// {
//     ProgramOptions opts;

//     int opt;
//     int long_index = 0;
//     while ((opt = getopt_long(argc, argv, short_opts, long_opts, &long_index)) != -1) {
//         switch (opt) {
//         case 'h':
//             opts.show_help = true;
//             break;

//         case 'i':
//             opts.use_interface = true;
//             if (optarg) { opts.interface_name = optarg; }
//             break;

//         case 'r':
//             opts.use_pcap = true;
//             opts.pcap_file = optarg;
//             break;

//         case '?':
//             usage(EXIT_FAILURE);
//         }
//     }

//     if (opts.use_interface && opts.use_pcap) {
//         std::cerr << "Error: -i/--interface and -r/--read cannot be used together.\n";
//         std::exit(EXIT_FAILURE);
//     }

//     return opts;
// }

int main(int argc, char *argv[])
{
    if (argc == 1) {
        usage(EXIT_FAILURE);
    }

    // ProgramOptions options = parse_arguments(argc, argv);
    // if (options.show_help) {
    //     usage(EXIT_SUCCESS);
    // } else if (options.use_interface) {
    //     char *device;
    //     char error_buffer[PCAP_ERRBUF_SIZE];
    //     pcap_t *handle;
    //     int timeout_limit = 10000; /* In milliseconds */

    //     // Select default interface
    //     device = (options.interface_name.empty() ? pcap_lookupdev(error_buffer) : options.interface_name.data());
    //     if (device == NULL) {
    //         printf("Error finding device: %s\n", error_buffer);
    //         return 1;
    //     }

    //     printf("listening on %s\n", device);

    //     /* Open device for live capture */
    //     handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, error_buffer);

    //     if (handle == NULL) {
    //         fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
    //         return 2;
    //     }

    //     if (pcap_loop(handle, 0, my_packet_handler, NULL) < 0) {
    //         std::cerr << std::format("\npcap_loop() failed: {}\n", pcap_geterr(handle));
    //         return EXIT_FAILURE;
    //     }
    // } else if (options.use_pcap) {
    //     std::cout << "Reading from pcap file: " << options.pcap_file << "\n";

    //     pcap_t *pcap_handler;
    //     char errbuf[PCAP_BUF_SIZE]{ '\0' };
    //     char source[PCAP_BUF_SIZE]{ '\0' };

    //     pcap_handler = pcap_open_offline(options.pcap_file.c_str(), errbuf);
    //     if (pcap_handler == nullptr) {
    //         std::cerr << std::format("pcap_open_offline() failed: {}", errbuf) << std::endl;
    //         return EXIT_FAILURE;
    //     }

    //     if (pcap_loop(pcap_handler, 0, my_packet_handler, NULL) < 0) {
    //         std::cerr << std::format("\npcap_loop() failed: {}\n", pcap_geterr(pcap_handler));
    //         return EXIT_FAILURE;
    //     }
    // } else {
    //     std::cerr << "Error: You must specify either -i/--interface or -r/--read.\n";
    //     return EXIT_FAILURE;
    // }

    return 0;
}