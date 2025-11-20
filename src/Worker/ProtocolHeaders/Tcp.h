#pragma once

#include <cinttypes>

#define TCP_HEADER_IS_FLAG_SET(header, flag) (((header)->flags & (flag)) != 0)

struct custom_tcp_header
{
    std::uint16_t src_port;// Source Port
    std::uint16_t dst_port;// Destination Port
    std::uint32_t seq_num;// Sequence Number
    std::uint32_t ack_num;// Acknowledgment Number
    std::uint8_t data_offx2;// Data Offset (4 bits) and Reserved (4 Bits)
    std::uint8_t flags;// TCP Flags
    std::uint16_t window;// Window Size
    std::uint16_t checksum;// Checksum
    std::uint16_t urgen;// Urgen Pointer
} __attribute__((packed));