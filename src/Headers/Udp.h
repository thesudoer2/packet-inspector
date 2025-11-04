#pragma once

#include <cinttypes>

struct custom_udp_header
{
    std::uint16_t src_port;// Source Port
    std::uint16_t dst_port;// Destination Port
    std::uint16_t len;// Header Length
    std::uint16_t checksum;// Header Checksum
} __attribute__((packed));