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
#include <chrono>

#include <cstdio>
#include <ctime>
#include <cinttypes>
#include <cstring>

#include <boost/beast/http.hpp>
#include <boost/beast/core/flat_buffer.hpp>

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


// Global flag for graceful shutdown
volatile sig_atomic_t shutdown_requested = 0;
pcap_t *handle;

inline void setup_signal_handlers(void (*handler)(int));
inline void signal_handler(int signum);

static std::chrono::steady_clock::time_point start_time;
static std::uint64_t number_of_processed_packets = 0;

inline void print_statistics();

inline void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) noexcept;
inline bool parse_and_print_http(const std::uint8_t *data, std::size_t len) noexcept;
inline void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) noexcept;


int main(int argc, char *argv[]) {
    DEBUG(std::cout << "Debug mode enabled..." << std::endl;)
    VERBOSE(std::cout << "Verbose mode enabled..." << std::endl;)

    // Setup signals
    setup_signal_handlers(signal_handler);

    if (argc == 1) {
        print_help(argv[0]);
        return EXIT_FAILURE;
    }

    VERBOSE(std::cout << std::unitbuf;);

    ProgramOptions options = parse_arguments(argc, argv);
    if (options.show_help) {
        print_help(argv[0]);
        return 0;
    }
    else if (options.use_interface) {
        char *device;
        char error_buffer[PCAP_ERRBUF_SIZE];
        int timeout_limit = 10; /* In milliseconds */

        // Select default interface
        device = (options.interface_name.empty() ? pcap_lookupdev(error_buffer) : options.interface_name.data());
        if (device == NULL) {
            std::cout << "Error finding device: " << error_buffer << std::endl;
            return 1;
        }

        std::cout << "listening on " << device << std::endl;

        /* Open device for live capture */
        handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, error_buffer);

        if (handle == NULL) {
            fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
            return 2;
        }

        struct pcap_pkthdr *header;
        const u_char *data;

        while (!shutdown_requested) {
            int ret = pcap_next_ex(handle, &header, &data);

            if (ret == 1) {
                // process packet
                my_packet_handler(nullptr, header, data);
            } else if (ret == 0) {
                // timeout, no packet yet
                continue;
            } else if (ret == -1) {
                fprintf(stderr, "pcap error: %s\n", pcap_geterr(handle));
                break;
            } else if (ret == -2) {
                // end of capture file
                break;
            }

        }

        // Print statistics at exit time
        print_statistics();

        pcap_close(handle);
    }
    else if (options.use_pcap) {
        std::cout << "Reading from pcap file: " << options.pcap_file << "\n";

        char errbuf[PCAP_BUF_SIZE]{ '\0' };
        char source[PCAP_BUF_SIZE]{ '\0' };

        handle = pcap_open_offline(options.pcap_file.c_str(), errbuf);
        if (handle == nullptr) {
            std::cerr << std::format("pcap_open_offline() failed: {}", errbuf) << std::endl;
            return EXIT_FAILURE;
        }

        start_time = std::chrono::steady_clock::now();

        struct pcap_pkthdr *header;
        const u_char *data;

        while (!shutdown_requested) {
            int ret = pcap_next_ex(handle, &header, &data);

            if (ret == 1) {
                // process packet
                my_packet_handler(nullptr, header, data);
            } else if (ret == 0) {
                // timeout, no packet yet
                continue;
            } else if (ret == -1) {
                fprintf(stderr, "pcap error: %s\n", pcap_geterr(handle));
                break;
            } else if (ret == -2) {
                // end of capture file
                break;
            }

        }

        // Print statistics at exit time
        print_statistics();

        pcap_close(handle);
    }
    else {
        std::cerr << "Error: You must specify either -i/--interface or -r/--read.\n";
        return EXIT_FAILURE;
    }

    return 0;
}

void setup_signal_handlers(void (*handler)(int))
{
    struct sigaction sigact;
    sigact.sa_handler = handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;

    sigaction(SIGINT, &sigact, nullptr);
    sigaction(SIGTERM, &sigact, nullptr);
}


void signal_handler(int signum)
{
    // async-signal-safe logging
    const char msg[] = "Signal received\n";
    write(STDERR_FILENO, msg, sizeof(msg)-1);

    const char stop_msg[] = "\n\n\033[1;31m**************** Stopping capture ****************\033[0;0m\n\n";
    write(STDERR_FILENO, stop_msg, sizeof(stop_msg)-1);

    shutdown_requested = 1;
}

void print_statistics()
{
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time
    );

    double seconds = duration.count() / 1000.0;
    double packets_per_sec = (seconds > 0) ? number_of_processed_packets / seconds : 0;

    std::cout << "\n=== Packet Processing Statistics ===\n";
    std::cout << "Total packets processed: " << number_of_processed_packets << "\n";
    std::cout << "Duration: " << std::fixed << std::setprecision(2)
                << seconds << " seconds\n";
    std::cout << "Packets per second: " << std::fixed // << std::setprecision(2)
                << packets_per_sec << "\n";
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) noexcept {
    std::cout << std::format("\n+++++++++++++++++++ Packet Number {} +++++++++++++++++++\n", ++number_of_processed_packets);

    std::cout << std::format("\n--- New Packet Recived (Length: {}, Captured: {})\n", packet_header->len, packet_header->caplen) << std::endl;

    // 01. Dissect Ethernet Header
    if (packet_header->caplen < sizeof(struct custom_ethernet_header)) {
        std::cout << "Packet too small for Ethernet header!" << std::endl;
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
            } else { // Same IP, differentiate by port
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
                DEBUG(if (vlan_tag_len != 0) std::cout << std::format(" (+ VLAN/TAG Header Len ({}) = {})", vlan_tag_len, vlan_tag_len + total_packet_length); std::cout << '\n');
                DEBUG(std::flush(std::cout));

                //////////////////////////////////////// Use DPI Engine (not implemented) ////////////////////////////////////////////
                if (th_sport == 80 || th_dport == 80 || th_sport == 8080 || th_dport == 8080 || th_sport == 443 || th_dport == 443) { // HTTP Port
                    std::cout << std::format("\t\tTCP Application Layer: HTTP (likely) -- Source port: {}, Destination port: {}\n", th_sport, th_dport);

                    VERBOSE(std::cout << std::format("\t\t\tHTTP Data (Length: {} bytes):\n", application_data_len));

                    // decide how many bytes we can safely inspect from capture
                    std::size_t bytes_to_print =
                      std::min((std::size_t)(packet_header->caplen - current_offset), application_data_len);

                    // Parse and print HTTP start-line + headers (safe, limited to headers)
                    VERBOSE(bool parse_result = parse_and_print_http(application_data, bytes_to_print););

                    // Keep existing verbose hexdump / text dump if BE_VERBOSE is enabled
                    VERBOSE(
                        if (parse_result == false) {
                            std::cout << "\t\t\t\t";
                            for (std::size_t i{0}; i < bytes_to_print; ++i) {
                                char c = payload[i];
                                if (isprint(static_cast<unsigned char>(c)))
                                    std::cout << c;
                                else
                                    std::cout << ".";
                                if ((i + 1) % 64 == 0) std::cout << "\n\t\t\t\t";
                            }
                            std::cout << '\n';
                        }
                    );
                } else {
                    std::cout << std::format(
                      "\t\tTCP Application Layer: Unhandled Application Protocol (Source port: {}, Destination port: "
                      "{})\n",
                      th_sport,
                      th_dport);
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

            // Handle UDP sessions
            Session::SessionKey current_key;
            current_key.l4proto = Session::LAYER4_PROTOCOLS::UDP;
            if (in_addr_t ip_src = ip_header->ip_src.s_addr, ip_dst = ip_header->ip_dst.s_addr; ip_src < ip_dst) {
                current_key.ip1 = ip_src;
                current_key.port1 = uh_sport;
                current_key.ip2 = ip_dst;
                current_key.port2 = uh_dport;
            } else if (ip_src > ip_dst) {
                current_key.ip1 = ip_dst;
                current_key.port1 = uh_dport;
                current_key.ip2 = ip_src;
                current_key.port2 = uh_sport;
            } else { // Same IP, differentiate by port
                current_key.ip1 = ip_src;
                current_key.ip2 = ip_dst; // Same IP
                current_key.port1 = std::min(uh_sport, uh_dport);
                current_key.port2 = std::max(uh_sport, uh_dport);
            }

            std::shared_ptr<Session::SessionCollection> session_manager = Session::SessionCollection::get_instance();
            auto [it, inserted] = session_manager->addSessionPair({current_key, nullptr});

            VERBOSE(
                if (inserted) { std::cout << "\t\t[NEW SESSION ESTABLISHED]\n"; session_manager->printSessions(); }
                else { std::cout << "\t\t[EXISTING SESSION]\n"; session_manager->printSession(current_key); }
            );

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
    std::cout << "Packet capture length: " << packet_header.caplen << std::endl;
    std::cout << "Packet total length " << packet_header.len << std::endl;
}

// Check if data appears to be valid HTTP text (not binary)
bool is_valid_http_data(const std::uint8_t *data, std::size_t len) noexcept
{
    if (data == nullptr || len == 0) return false;

    // Check first line for valid HTTP request/response pattern
    // Look for common HTTP methods or HTTP/ version string
    std::string_view sv(reinterpret_cast<const char*>(data), std::min(len, (size_t)16));

    // Check if starts with common HTTP methods
    if (!(sv.starts_with("GET ") || sv.starts_with("POST ") ||
        sv.starts_with("PUT ") || sv.starts_with("DELETE ") ||
        sv.starts_with("HEAD ") || sv.starts_with("OPTIONS ") ||
        sv.starts_with("PATCH ") || sv.starts_with("TRACE ") ||
        sv.starts_with("CONNECT ") || sv.starts_with("HTTP/")))
    {
        return false;
    }

    // Check for excessive binary/control characters in first N bytes
    size_t check_len = std::min(len, (size_t)256);
    int binary_count = 0;
    int printable_count = 0;

    for (size_t i = 0; i < check_len; ++i) {
        unsigned char c = data[i];

        // Allow common HTTP characters: printable ASCII, \r, \n, \t
        if ((c >= 32 && c <= 126) || c == '\r' || c == '\n' || c == '\t') {
            ++printable_count;
        } else {
            ++binary_count;
        }
    }

    // If more than 10% binary characters, likely not HTTP
    if (check_len > 0 && binary_count * 10 > check_len) {
        return false;
    }

    return true;
}

bool parse_and_print_http(const std::uint8_t *data, std::size_t len) noexcept
{
    if (data == nullptr || len == 0) return false;

    // First check if data appears to be valid HTTP
    if (!is_valid_http_data(data, len)) {
        return false;
    }

    std::string_view sv(reinterpret_cast<const char *>(data), len);

    // Locate end of headers
    size_t header_end = sv.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        header_end = sv.find("\n\n");
        if (header_end != std::string_view::npos) {
            header_end += 2; // Length of "\n\n"
        }
    } else {
        header_end += 4; // Length of "\r\n\r\n"
    }

    // Limit parse length to avoid huge allocations when headers absent
    size_t parse_len = (header_end == std::string_view::npos)
                       ? std::min(len, (size_t)4096)
                       : header_end;

    std::string headers_str(sv.substr(0, parse_len));
    std::istringstream iss(headers_str);
    std::string line;

    // Parse start-line
    if (!std::getline(iss, line)) return false;

    // Remove trailing \r if present
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    // Additional validation: check if first line contains only printable characters
    for (unsigned char c : line) {
        if (c < 32 && c != '\t') {  // Control characters except tab
            return false;
        }
    }

    // Parse method/version and URL/status
    std::string first, second, third;
    {
        std::istringstream start(line);
        start >> first >> second >> third;
    }

    // Validate we have at least 2 tokens
    if (first.empty() || second.empty()) {
        return false;
    }

    // Determine if request or response
    bool is_request = true;
    std::string method, url, version;
    int status_code = 0;
    std::string reason_phrase;

    if (!first.empty() && first.find("HTTP/") == 0) {
        // Response line: HTTP/1.1 200 OK
        is_request = false;
        version = first;

        // Parse status code
        try {
            status_code = std::stoi(second);
            // Validate status code range
            if (status_code < 100 || status_code > 599) {
                return false;
            }
        } catch (...) {
            return false;
        }

        // Reason phrase is rest of line after status code
        size_t pos = line.find(second);
        if (pos != std::string::npos) {
            pos += second.length();
            while (pos < line.length() && std::isspace(static_cast<unsigned char>(line[pos]))) {
                ++pos;
            }
            if (pos < line.length()) {
                reason_phrase = line.substr(pos);
            }
        }
    } else {
        // Request line: GET /path HTTP/1.1
        is_request = true;
        method = first;
        url = second;
        version = third;

        // Validate HTTP version format
        if (version.find("HTTP/") != 0) {
            return false;
        }
    }

    // Parse headers
    auto trim = [](std::string &s) {
        // Trim leading whitespace
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
            s.erase(s.begin());
        }
        // Trim trailing whitespace
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
            s.pop_back();
        }
    };

    auto is_valid_header_line = [](const std::string& s) -> bool {
        for (unsigned char c : s) {
            // Allow printable ASCII and common whitespace
            if (c < 32 && c != '\t') {
                return false;
            }
            if (c > 126) {  // Non-ASCII character
                return false;
            }
        }
        return true;
    };

    std::map<std::string, std::string> headers;
    while (std::getline(iss, line)) {
        // Remove trailing \r
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        // Empty line marks end of headers
        if (line.empty()) break;

        // Validate header line doesn't contain binary data
        if (!is_valid_header_line(line)) {
            return false;
        }

        // Find colon separator
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;

        std::string name = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        trim(name);
        trim(value);

        if (!name.empty()) {
            headers[name] = value;
        }
    }

    // Print results
    std::cout << "\t\t\t\t=== HTTP " << (is_request ? "Request" : "Response") << " ===\n";

    if (is_request) {
        std::cout << "\t\t\t\tMethod : " << method << "\n";
        std::cout << "\t\t\t\tURL    : " << url << "\n";
        std::cout << "\t\t\t\tVersion: " << version << "\n";
    } else {
        std::cout << "\t\t\t\tVersion: " << version << "\n";
        std::cout << "\t\t\t\tStatus : " << status_code;
        if (!reason_phrase.empty()) {
            std::cout << " " << reason_phrase;
        }
        std::cout << "\n";
    }

    // Print headers
    for (const auto &[name, value] : headers) {
        std::cout << "\t\t\t\t" << name << ": " << value << "\n";
    }
    std::cout << '\n';

    return true;
}
