#pragma once

#include <netinet/ether.h>

#include <cinttypes>

// Define a packed Ethernet header to prevent compiler padding
struct custom_ethernet_header
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    std::uint16_t ether_type; /* IP, ARP, RARP, etc. */
} __attribute__((packed));