#pragma once

#include <cinttypes>

/******* Add ETHERTYPE_ definitions if system's net/ethernet.h doesn't have them *******/

// VLAN (802.1Q)
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

// Define a packed VLAN tag to prevent compiler padding
struct custom_vlan_tag
{
    std::uint16_t vlan_tci;// Tag Control Information (Priority, CFI, VLAN ID)
    std::uint16_t vlan_proto;// EtherType of the encapsulated protocol
} __attribute__((packed));