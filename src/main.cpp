#include <arpa/inet.h> // For inet_ntoa
#include <net/ethernet.h> // For ether_header and ETHERTYPE_XXX (on Linux)
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/sctp.h>

#include <string>
#include <format>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <algorithm>
#include <ranges>
#include <span>

#include <cstdio>
#include <ctime>
#include <cinttypes>
#include <cstring>

#include <pcap.h>

#include "Session.h"
#include "OptionHandler.h"
#include "SessionCollection.h"

// Define a packed Ethernet header to prevent compiler padding
struct custom_ethernet_header {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    std::uint16_t ether_type;                    /* IP, ARP, RARP, etc. */
} __attribute__((packed));

// Define a packed VLAN tag to prevent compiler padding
struct custom_vlan_tag {
    std::uint16_t vlan_tci;   // Tag Control Information (Priority, CFI, VLAN ID)
    std::uint16_t vlan_proto; // EtherType of the encapsulated protocol
} __attribute__((packed));

// Define a packed IP header structure that matches the wire format
struct custom_ip_header {
    std::uint8_t  ip_vhl;   // Version (4 bits) and Header Length (4 bits)
    std::uint8_t  ip_tos;   // Type of Service
    std::uint16_t ip_len;   // Total Length
    std::uint16_t ip_id;    // Identification
    std::uint16_t ip_off;   // Fragment Offset
    std::uint8_t  ip_ttl;   // Time To Live
    std::uint8_t  ip_p;     // Protocol
    std::uint16_t ip_sum;   // Header Checksum
    struct in_addr ip_src;  // Source IP Address
    struct in_addr ip_dst;  // Destination IP Address
} __attribute__((packed));

struct custom_tcp_header {
    std::uint16_t src_port;    // Source Port
    std::uint16_t dst_port;    // Destination Port
    std::uint32_t seq_num;     // Sequence Number
    std::uint32_t ack_num;     // Acknowledgment Number
    std::uint8_t  data_offx2;  // Data Offset (4 bits) and Reserved (4 Bits)
    std::uint8_t  flags;       // TCP Flags
    std::uint16_t window;      // Window Size
    std::uint16_t checksum;    // Checksum
    std::uint16_t urgen;       // Urgen Pointer
} __attribute__((packed));

struct custom_udp_header {
    std::uint16_t src_port;    // Source Port
    std::uint16_t dst_port;    // Destination Port
    std::uint16_t len;         // Header Length
    std::uint16_t checksum;    // Header Checksum
} __attribute__((packed));


/******* Add ETHERTYPE_ definitions if system's net/ethernet.h doesn't have them *******/

// VLAN (802.1Q)
#ifndef ETHERTYPE_VLAN
# define ETHERTYPE_VLAN 0x8100
#endif

// IP
#ifndef ETHERTYPE_IP
# define ETHERTYPE_IP 0x0800
#endif

// ARP
#ifndef ETHERTYPE_ARP
# define ETHERTYPE_ARP 0x0806
#endif

// AARP
#ifndef ETHERTYPE_AARP
#define ETHERTYPE_AARP 0x80F7
#endif

// LOOPBACK
#ifndef ETHERTYPE_LOOPBACK
# define ETHERTYPE_LOOPBACK 0x0060
#endif

// TCP
#ifndef IPPROTO_TCP
# define IPPROTO_TCP 0x0006
#endif

// UDP
#ifndef IPPROTO_UDP
# define IPPROTO_UDP 0x0023
#endif


#define TCP_HEADER_IS_FLAG_SET(header, flag) (((header)->flags & (flag)) != 0)

#ifdef BE_VERBOSE
# define VERBOSE(x) x
#else
# define VERBOSE(x)
#endif

#ifdef DO_DEBUGGING
# define DEBUG(x) x
#else
# define DEBUG(x)
#endif


inline void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) noexcept;
inline void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) noexcept;


int main(int argc, char *argv[]) {
    if (argc == 1) {
        print_help(argv[0]);
        return EXIT_FAILURE;
    }

    ProgramOptions options = parse_arguments(argc, argv);
    if (options.show_help) {
        print_help(argv[0]);
        return 0;
    }
    else if (options.use_interface) {
        char *device;
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        int timeout_limit = 10000; /* In milliseconds */

        // Select default interface
        device = (options.interface_name.empty() ? pcap_lookupdev(error_buffer) : options.interface_name.data());
        if (device == NULL) {
            printf("Error finding device: %s\n", error_buffer);
            return 1;
        }

        printf("listening on %s\n", device);

        /* Open device for live capture */
        handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, error_buffer);

        if (handle == NULL) {
            fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
            return 2;
        }

        if (pcap_loop(handle, 0, my_packet_handler, NULL) < 0) {
            std::cerr << std::format("\npcap_loop() failed: {}\n", pcap_geterr(handle));
            return EXIT_FAILURE;
        }
    }
    else if (options.use_pcap) {
        std::cout << "Reading from pcap file: " << options.pcap_file << "\n";

		////////////////////// DPI Initialization ////////////////////////
		;
		/////////////////////////////////////////////////////////////////

        pcap_t* pcap_handler;
        char errbuf[PCAP_BUF_SIZE] { '\0' };
        char source[PCAP_BUF_SIZE] { '\0' };

        pcap_handler = pcap_open_offline(options.pcap_file.c_str(), errbuf);
        if (pcap_handler == nullptr) {
            std::cerr << std::format("pcap_open_offline() failed: {}", errbuf) << std::endl;
            return EXIT_FAILURE;
        }

        if (pcap_loop(pcap_handler, 0, my_packet_handler, NULL) < 0) {
            std::cerr << std::format("\npcap_loop() failed: {}\n", pcap_geterr(pcap_handler));
            return EXIT_FAILURE;
        }
    }
    else {
        std::cerr << "Error: You must specify either -i/--interface or -r/--read.\n";
        return EXIT_FAILURE;
    }

    return 0;
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) noexcept {
    static std::uint64_t packet_counter {1};

    std::cout << std::format("\n+++++++++++++++++++ Packet Number {} +++++++++++++++++++\n", packet_counter++);

    std::cout << std::format("\n--- New Packet Recived (Length: {}, Captured: {})\n", packet_header->len, packet_header->caplen) << std::endl;

    // 01. Dissect Ethernet Header
    if (packet_header->caplen < sizeof(struct custom_ethernet_header)) {
        printf("Packet too small for Ethernet header!\n");
        return;
    }

    struct custom_ethernet_header *eth_header = (struct custom_ethernet_header*)packet_body;
    uint16_t eth_header_len = sizeof(struct custom_ethernet_header);
    uint16_t ether_type = ntohs(eth_header->ether_type);
    const u_char *payload = packet_body + sizeof(struct custom_ethernet_header);
    size_t current_offset = sizeof(struct custom_ethernet_header); // Tracks current position in packet_body

    std::cout << "Packet header type: ETHERNET\n";

    // Print Source MAC Address
    VERBOSE({
        // Create a span for the mac address array
        std::span<u_char> mac_addr_span(eth_header->ether_shost, ETHER_ADDR_LEN);

        // Create a transformed view that converts to hex
        auto hex_view = mac_addr_span | std::views::transform([](u_char c) {
            return std::format("{:02X}", c);
        }) | std::views::join_with(':');

        // Print the result
        std::string hex_string;
        for (const auto& item : hex_view) {
            hex_string += item;
        }
        std::cout << std::format("{:<26}{}", "\tSource MAC Address: ", hex_string) << '\n';
    });

    // Print Destination MAC Address
    VERBOSE({
        // Create a span for the mac address array
        std::span<u_char> mac_addr_span(eth_header->ether_dhost, ETHER_ADDR_LEN);

        // Create a transformed view that converts to hex
        auto hex_view = mac_addr_span | std::views::transform([](u_char c) {
            return std::format("{:02X}", c);
        }) | std::views::join_with(':');

        // Print the result
        std::string hex_string;
        for (const auto& item : hex_view) {
            hex_string += item;
        }
        std::cout << std::format("{:<26}{}", "\tDestination MAC Address: ", hex_string) << '\n';
    });

    // 02. Handle VLAN if present
    std::uint16_t vlan_tag_len = 0;
    if (ether_type == ETHERTYPE_VLAN) {
        vlan_tag_len = sizeof(struct custom_vlan_tag);

        std::cout << "Ethernet header has VLAN tag\n";

        if (packet_header->caplen < current_offset + vlan_tag_len) {
            std::cerr << "Packet too small for VLAN tag!\n";
            return;
        }

        struct custom_vlan_tag *vlan = (struct custom_vlan_tag*)payload;

        std::cout << std::format("\tVLAN TCI: {:#04x}\n", ntohs(vlan->vlan_tci));
        std::cout << std::format("\tVLAN Protocol: {:#04x}\n", ntohs(vlan->vlan_proto));

        ether_type = ntohs(vlan->vlan_proto); // The actual protocol after VLAN
        payload += vlan_tag_len;
        current_offset += vlan_tag_len;
    }

    // 03. Dissect Layer3 Protocol
    if (ether_type == ETHERTYPE_IP) {
        // Dissect IP Header
        std::cout << "Packet header type: IP\n";

        // 20 bytes is the minimum IP header size
        if (packet_header->caplen < current_offset + sizeof(struct custom_ip_header)) {
            std::cerr << std::format("Packet too small for IP header! (Caplen: {}, Expected min: {})\n",
                   packet_header->caplen, current_offset + sizeof(struct custom_ip_header));
            return;
        }

        struct custom_ip_header *ip_header = (struct custom_ip_header*)(payload);

        // Extracting Version and Header Length from ip header
        unsigned int ip_version = (ip_header->ip_vhl >> 4) & 0x0F;
        unsigned int ip_header_length = (ip_header->ip_vhl & 0x0F) * 4; // Length in 32-bit words, multiply by 4 for bytes

        // Perform byte order conversion for multi-byte fields
        std::uint16_t total_length = ntohs(ip_header->ip_len);
        std::uint16_t identification = ntohs(ip_header->ip_id);
        std::uint16_t fragment_offset = ntohs(ip_header->ip_off); // Needs more parsing for flags/offset

        VERBOSE(std::cout << std::format("\tIP Version: {}\n", ip_version));
        VERBOSE(std::cout << std::format("\tIP Header Length: {} Bytes\n", ip_header_length));
        VERBOSE(std::cout << std::format("\tTotal Length (incl. header): {} Bytes\n", total_length));
        VERBOSE(std::cout << std::format("\tType of Service (ToS): {:#04x}\n",(int)ip_header->ip_tos));
        VERBOSE(std::cout << std::format("\tIdentification: {}\n", identification));
        VERBOSE(std::cout << std::format("\tTTL: {}\n", (int)ip_header->ip_ttl));
        VERBOSE(std::cout << std::format("\tProtocol: {}\n", (int)ip_header->ip_p));
        VERBOSE(std::cout << std::format("\tChecksum: {:#04x}\n", ntohs(ip_header->ip_sum)));
        VERBOSE(std::cout << std::format("\tSource IP: {}\n", inet_ntoa(ip_header->ip_src)));
        VERBOSE(std::cout << std::format("\tDestination IP: {}\n", inet_ntoa(ip_header->ip_dst)));

        // Move payload pointer past the IP header (include options)
        payload += ip_header_length;
        current_offset += ip_header_length;

        // Dissect TCP Header (if IP protocol is TCP)
        if (ip_header->ip_p == IPPROTO_TCP) {
            std::cout << "\tProtocol Type: TCP\n";

            if (packet_header->caplen < current_offset + sizeof(struct custom_tcp_header)) {
                std::cerr << "Packet too small for TCP header!\n";
                return;
            }

            const custom_tcp_header *tcp_header = (struct custom_tcp_header*)payload;

            // Extract the TCP header length from the 'Data Offset' field
            std::uint32_t th_len = ((tcp_header->data_offx2 >> 4) & 0X0F) * 4;
            std::uint16_t th_sport = ntohs(tcp_header->src_port);
            std::uint16_t th_dport = ntohs(tcp_header->dst_port);
            std::uint16_t th_seqnum = ntohl(tcp_header->seq_num);
            std::uint16_t th_acknum = ntohl(tcp_header->ack_num);

            VERBOSE(std::cout << std::format("\t\tSource Port: {}\n", th_sport));
            VERBOSE(std::cout << std::format("\t\tDestination Port: {}\n", th_dport));
            VERBOSE(std::cout << std::format("\t\tSequence Number: {}\n", th_seqnum));
            VERBOSE(std::cout << std::format("\t\tAcknowledgement Number: {}\n", th_acknum));
            VERBOSE(std::cout << std::format("\t\tTCP Header Length: {}\n", th_len));

            // Handle TCP sessions
            Session::SessionKey current_key;
            current_key.l4proto = Session::LAYER4_PROTOCOLS::TCP;
            if (in_addr_t ip_src = ip_header->ip_src.s_addr, ip_dst = ip_header->ip_dst.s_addr; ip_src < ip_dst) {
                current_key.ip1 = ip_src;
                current_key.port1 = th_sport;
                current_key.ip2 = ip_dst;
                current_key.port2 = th_dport;
            } else if (ip_src > ip_dst) {
                current_key.ip1 = ip_dst;
                current_key.port1 = th_dport;
                current_key.ip2 = ip_src;
                current_key.port2 = th_sport;
            } else { // Smae IP, differentiate by port
                current_key.ip1 = ip_src;
                current_key.ip2 = ip_dst; // Same IP
                current_key.port1 = std::min(th_sport, th_dport);
                current_key.port2 = std::max(th_sport, th_dport);
            }

            std::shared_ptr<Session::SessionCollection> session_manager = Session::SessionCollection::get_instance();
            auto [it, inserted] = session_manager->addSessionPair({current_key, nullptr});

            VERBOSE(
                if (inserted) { std::cout << "\t\t[NEW SESSION ESTABLISHED]\n"; session_manager->printSessions(); }
                else { std::cout << "\t\t[EXISTING SESSION]\n"; session_manager->printSession(current_key); }
            );

            VERBOSE(std::cout << "\t\tFlags: ");
            VERBOSE(if (TCP_HEADER_IS_FLAG_SET(tcp_header, TH_FIN)) std::cout << "[FIN]");
            VERBOSE(if (TCP_HEADER_IS_FLAG_SET(tcp_header, TH_SYN)) std::cout << "[SYN]");
            VERBOSE(if (TCP_HEADER_IS_FLAG_SET(tcp_header, TH_RST)) std::cout << "[RST]");
            VERBOSE(if (TCP_HEADER_IS_FLAG_SET(tcp_header, TH_PUSH)) std::cout << "[PUSH]");
            VERBOSE(if (TCP_HEADER_IS_FLAG_SET(tcp_header, TH_ACK)) std::cout << "[ACK]");
            VERBOSE(if (TCP_HEADER_IS_FLAG_SET(tcp_header, TH_URG)) std::cout << "[URG]");
            VERBOSE(std::cout << '\n');

            VERBOSE(std::cout << std::format("\t\tWindow Size: {}\n", ntohs(tcp_header->window)));
            VERBOSE(std::cout << std::format("\t\tChecksum: {:#04x}\n", ntohs(tcp_header->checksum)));
            VERBOSE(std::cout << std::format("\t\tUrgent Pointer: {}\n", ntohs(tcp_header->urgen)));

            // Advance payload pointer past TCP header
            payload += th_len;
            current_offset += th_len;

            // Application data layer
            const std::uint8_t *application_data = payload;
            std::size_t application_data_len = total_length - ip_header_length - th_len;

            if (application_data_len > 0) {
                DEBUG(std::uint16_t total_packet_length = eth_header_len + total_length);
                DEBUG(std::cout << "\t\tTCP Header has application data:\n");
                DEBUG(std::cout << std::format("\t\t\tEthernet Header Length: {}\n", eth_header_len));
                DEBUG(if (vlan_tag_len != 0) std::cout << std::format("\t\t\tVLAN/TAG Header Length: {}\n", vlan_tag_len));
                DEBUG(std::cout << std::format("\t\t\tIP Header Length: {}\n", ip_header_length));
                DEBUG(std::cout << std::format("\t\t\tTCP Header Length: {}\n", th_len));
                DEBUG(std::cout << std::format("\t\t\tApplication Layer Length: {}\n", application_data_len));
                DEBUG(std::cout << std::format("\t\t\tCurrent Packet Offset: {}\n", current_offset));
                DEBUG(std::cout << std::format("\t\t\tTotal Layers Length (Layer 3 + Layer 4 + ... + Layer 7): {}\n", total_length));
                DEBUG(std::cout << std::format("\t\t\tTotal Packet Length (Layer 2 + Layer 3 + Layer 4 + ... + Layer 7): {}", total_packet_length));
                DEBUG(if (vlan_tag_len != 0) std::cout << std::format(" (+ VLAN/TAG Header Len ({}) = {})", vlan_tag_len, vlan_tag_len + total_packet_length); std::cout << '\n');
                DEBUG(std::flush(std::cout));

                //////////////////////////////////////// Use DPI Engine (not implemented) ////////////////////////////////////////////
                if (th_sport == 80 || th_dport == 80 || th_sport == 8080 || th_dport == 8080 || th_sport == 443 || th_dport == 443) { // HTTP Port
                    std::cout << std::format("\t\tTCP Application Layer: HTTP (likely) -- Source port: {}, Destination port: {}\n", th_sport, th_dport);

                    VERBOSE(std::cout << std::format("\t\t\tHTTP Data (Length: {} bytes):\n", application_data_len));

                    // Print a hexdump of the application data
                    VERBOSE(
                        std::size_t bytes_to_print = std::min((std::size_t)(packet_header->caplen - current_offset), application_data_len);
                        std::cout << "\t\t\t\t";
                        for (std::size_t i {}; i < bytes_to_print; ++i) {
                            char c = payload[i];

                            if (isprint(c)) std::cout << c;
                            else std::cout << ".";

                            if ((i + 1) % 32 == 0) std::cout << "\n\t\t\t\t";
                        }

                        std::cout << '\n';
                    );
                } else {
                    std::cout << std::format("\t\tTCP Application Layer: Unhandled Application Protocol (Source port: {}, Destination port: {})\n", th_sport, th_dport);
                }
                ////////////////////////////////////////////////////////////////////////////////////////////////////

                VERBOSE(std::cout << std::format("\t\t[TCP Data Payload starts here, length {} bytes]\n", application_data_len));
            }
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            std::cout << "\tProtocol Type: UDP\n";

            if (packet_header->caplen < current_offset + sizeof(struct custom_udp_header)) {
                std::cerr << "Packet too small for UDP header!\n";
                return;
            }

            struct custom_udp_header *udp_header = (struct custom_udp_header*)payload;

            std::uint16_t uh_sport = ntohs(udp_header->src_port);
            std::uint16_t uh_dport = ntohs(udp_header->dst_port);
            std::uint16_t uh_len = ntohs(udp_header->len);
            std::uint16_t uh_chsum = ntohs(udp_header->checksum);

            VERBOSE(std::cout << std::format("\t\tSource Port: {}\n", uh_sport));
            VERBOSE(std::cout << std::format("\t\tDestination Port: {}\n", uh_dport));
            VERBOSE(std::cout << std::format("\t\tHeader Length: {}\n", uh_len));
            VERBOSE(std::cout << std::format("\t\tChecksum: {:#04x}\n", uh_chsum));

            // Advance payload pointer past UDP header
            payload += sizeof(struct custom_udp_header);
            current_offset += sizeof(struct custom_udp_header);

            // Application data layer
            const std::uint8_t* application_data = payload;
            std::size_t application_data_len = uh_len - sizeof(struct custom_udp_header);

            if (application_data_len > 0) {
                VERBOSE(std::cout << std::format("\t\t[UDP Data Payload starts here, length {} bytes]\n", application_data_len));

                if (uh_sport == 53 || uh_dport == 53) { // DNS port
                    std::cout << std::format("\t\tUDP Application Layer: DNS (likely) -- Source port: {}, Destination port: {}\n", uh_sport, uh_dport);

                    VERBOSE(std::cout << std::format("\t\t\tDNS Data (Length: {} bytes):\n", application_data_len));

                    // Print a hexdump of the application data
                    VERBOSE(
                        std::size_t bytes_to_print = std::min((std::size_t)(packet_header->caplen - current_offset), application_data_len);

                        std::cout << "\t\t\t\t";
                        for (std::size_t i {}; i < bytes_to_print; ++i) {
                            char c = payload[i];

                            if (isprint(c)) std::cout << c;
                            else std::cout << ".";

                            if ((i + 1) % 32 == 0) std::cout << "\n\t\t\t\t";
                        }

                        std::cout << "\n";

                        std::cout << "\t\t\t\t";
                        for (std::size_t i {}; i < bytes_to_print; ++i) {
                            std::cout << std::hex << std::setw(2) << std::setfill('0') << (std::uint32_t)payload[i];
                            if ((i + 1) % 16 == 0) std::cout << "\n\t\t\t\t";
                            else std::cout << ' ';
                        }

                        std::cout << "\n";
                    );
                } else {
                    std::cout << std::format("\t\tUDP Application Layer: Unhandled Application Protocol (Source port: {}, Destination port: {})\n", uh_sport, uh_dport);
                }
            }
        }

        std::flush(std::cout);
    } else if (ether_type == ETHERTYPE_ARP) { // Assuming ETHERTYPE_AARP and ETHERTYPE_LOOPBACK are correctly defined or you add them
        std::cout << "Packet header type: ARP\n";
    }
    else {
        std::cout << std::format("Packet header type: UNHANDLED ({:#04x})\n", ether_type);
    }
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) noexcept {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}
