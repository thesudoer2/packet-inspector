# Packet Inspector

Packet Inspector is a C++20-based network packet analysis tool designed for live packet capture and offline PCAP file inspection. It provides detailed, human-readable output of Ethernet, VLAN, IP, TCP, and UDP headers, with special handling for HTTP and DNS traffic. The tool is built around the `libpcap` library and includes TCP session tracking for advanced traffic analysis.

## Features

- **Live Packet Capture**: Listen on a specified network interface to inspect packets in real time.
- **PCAP File Analysis**: Read and analyze packets from a provided `.pcap` capture file.
- **Protocol Dissection**: Parses and displays details for Ethernet, VLAN, IP, TCP, and UDP headers.
- **TCP Session Tracking**: Manages and displays TCP session information.
- **Application Layer Hints**: Highlights likely HTTP and DNS traffic by inspecting port numbers.
- **Verbose and Debug Modes**: Optional detailed output for protocol fields and application data (using compiler flags).
- **Hexdump**: Visualizes application payloads in both ASCII and hexadecimal representations.
- **Cross-platform**: Should work on any Unix-like system with `libpcap`.

## Usage

```sh
./packet_inspector [OPTIONS]
```

### Options

- `-i, --interface [IFACE]`
  Listen on the given network interface (omit `IFACE` to use the system default).
- `-r, --read <PCAP>`
  Read packets from a `.pcap` file instead of live capture.
- `-h, --help`
  Show help message.

> **Note:** `-i` and `-r` are mutually exclusive.

## Example

Capture live packets on the default interface:
```sh
./packet_inspector -i
```

Analyze packets from a file:
```sh
./packet_inspector -r capture.pcap
```

## Build

This project uses CMake (minimum version 3.22):

```sh
mkdir build && cd build
cmake ..
make
```

### Requirements

- C++23 compiler (tested with GCC 13+ and Clang 16+)
- [libpcap](https://www.tcpdump.org/)
- CMake 3.22 or higher

## Output Example

When run, Packet Inspector prints detailed information about each packet, such as:

- Source and destination MAC addresses
- VLAN tags (if present)
- IP version, header length, source and destination IPs
- TCP/UDP source/destination ports, flags, sequence numbers
- Application layer guesses (HTTP, DNS)
- Hexdump of payload (when verbose/debug is enabled)

## Project Structure

- `src/main.cpp` - Core packet capture, dissection, and output
- `src/OptionHandler.cpp` - Command-line option parsing and help
- `src/Session.cpp`, `src/SessionCollection.cpp` - TCP session management
