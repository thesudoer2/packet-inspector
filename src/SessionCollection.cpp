#include "Session.h"

#include <arpa/inet.h> // For inet_ntoa
#include <netinet/in.h> // For in_addr

#include <cstring>

#include <iostream>
#include <format>

#include "SessionCollection.h"

namespace Session {

bool SessionKey::operator<(const SessionKey& other) const noexcept {
    if (ip1 != other.ip1) return ip1 < other.ip1;
    if (port1 != other.port1) return port1 < other.port1;
    if (ip2 != other.ip2) return ip2 < other.ip2;
    return port2 < other.port2;
}

std::pair<SessionCollection::SessionContainerIterator, bool>
SessionCollection::addSessionPair(std::pair<SessionKey, std::shared_ptr<SessionBase>> session_pair) {
    return _active_sessions.try_emplace(session_pair.first, std::move(session_pair.second));
}

VERBOSE(
void SessionCollection::printSession(const SessionKey& key) const noexcept {
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &key.ip1, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &key.ip2, dst_ip_str, INET_ADDRSTRLEN);

    auto it = _active_sessions.find(key);
    if (it != _active_sessions.end()) {
        std::cout << std::format("\t\tSession Key: ({}:{} <-> {}:{} / {}):\n", src_ip_str, key.port1, dst_ip_str, key.port2, LAYER4_PROTOCOL_NAMES[static_cast<std::uint8_t>(key.l4proto)]);
    } else {
        std::cout << std::format("\t\tSession not found for key: ({}:{} <-> {}:{} / {}):\n",
                src_ip_str, key.port1, dst_ip_str, key.port2, LAYER4_PROTOCOL_NAMES[static_cast<std::uint8_t>(key.l4proto)]);
    }
}

void SessionCollection::printSessions() const noexcept {
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    std::size_t counter {1};
    for (const auto& [key, session] : _active_sessions) {
        inet_ntop(AF_INET, &key.ip1, src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &key.ip2, dst_ip_str, INET_ADDRSTRLEN);

        std::cout << std::format("\t\t{}. Session Key: ({}:{} <-> {}:{} / {}):\n", counter++, src_ip_str, key.port1, dst_ip_str, key.port2, LAYER4_PROTOCOL_NAMES[static_cast<std::uint8_t>(key.l4proto)]);

        std::memset(src_ip_str, '\0', INET_ADDRSTRLEN);
        std::memset(dst_ip_str, '\0', INET_ADDRSTRLEN);
    }
}
) // VERBOSE

} // namespace Session