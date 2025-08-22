#include "OptionHandler.h"

#include <format>
#include <iostream>

#include <getopt.h>

void print_help(const char* program_name) noexcept {
    std::cout << "Usage:\n"
              << std::format("\t{} [OPTIONS]\n", program_name)
              << "Options:\n"
              << "  -i, --interface [IFACE]   Listen on given interface (don't write IFACE for using default)\n"
              << "  -r, --read <PCAP>         Read packets from a pcap file\n"
              << "  -h, --help                Show this help message\n"
              << "\nNote: -i and -r are mutually exclusive.\n";
}

ProgramOptions parse_arguments(int argc, char* argv[]) noexcept {
    ProgramOptions opts;

    const char* short_opts = "hi::r:"; // i:: means optional argument
    const struct option long_opts[] = {
        {"help",      no_argument,       nullptr, 'h'},
        {"interface", optional_argument, nullptr, 'i'},
        {"read",      required_argument, nullptr, 'r'},
        {nullptr,     0,                 nullptr,  0 }
    };

    int opt;
    int long_index = 0;

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &long_index)) != -1) {
        switch (opt) {
            case 'h':
                opts.show_help = true;
                break;

            case 'i':
                opts.use_interface = true;
                if (optarg) {
                    opts.interface_name = optarg;
                }
                break;

            case 'r':
                opts.use_pcap = true;
                opts.pcap_file = optarg;
                break;

            case '?': // Invalid option
                print_help(argv[0]);
                std::exit(EXIT_FAILURE);
        }
    }

    if (opts.use_interface && opts.use_pcap) {
        std::cerr << "Error: -i/--interface and -r/--read cannot be used together.\n";
        std::exit(EXIT_FAILURE);
    }

    return opts;
}