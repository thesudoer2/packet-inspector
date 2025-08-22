#pragma once

#include <string>

struct ProgramOptions {
    bool show_help     { false };
    bool use_interface { false };
    bool use_pcap      { false };
    std::string interface_name;
    std::string pcap_file;
};

void print_help(const char* program_name) noexcept;
ProgramOptions parse_arguments(int argc, char* argv[]) noexcept;