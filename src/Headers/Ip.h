#pragma once

#include <cinttypes>

// IP
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

// Define a packed IP header structure that matches the wire format
struct custom_ip_header
{
    std::uint8_t ip_vhl;// Version (4 bits) and Header Length (4 bits)
    std::uint8_t ip_tos;// Type of Service
    std::uint16_t ip_len;// Total Length
    std::uint16_t ip_id;// Identification
    std::uint16_t ip_off;// Fragment Offset
    std::uint8_t ip_ttl;// Time To Live
    std::uint8_t ip_p;// Protocol
    std::uint16_t ip_sum;// Header Checksum
    struct in_addr ip_src;// Source IP Address
    struct in_addr ip_dst;// Destination IP Address
} __attribute__((packed));