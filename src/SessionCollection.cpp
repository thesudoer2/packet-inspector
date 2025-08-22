#include "Session.h"

#include <arpa/inet.h> // For inet_ntoa
#include <netinet/in.h> // For in_addr

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
    auto it = _active_sessions.find(key);
    if (it != _active_sessions.end()) {
        std::cout << std::format("\t\tSession Key: ({}:{} <-> {}:{}):\n", inet_ntoa(in_addr{key.ip1}), key.port1, inet_ntoa(in_addr{key.ip2}), key.port2);
    } else {
        std::cout << std::format("\t\tSession not found for key: ({}:{} <-> {}:{}):\n",
                inet_ntoa(in_addr{key.ip1}), key.port1, inet_ntoa(in_addr{key.ip2}), key.port2);
    }
}

void SessionCollection::printSessions() const noexcept {
    std::size_t counter {1};
    for (const auto& [key, info] : _active_sessions) {
        std::cout << std::format("\t\t{}. Session Key: ({}:{} <-> {}:{}):\n", counter++, inet_ntoa(in_addr{key.ip1}), key.port1, inet_ntoa(in_addr{key.ip2}), key.port2);
    }
}
) // VERBOSE

} // namespace Session