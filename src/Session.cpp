#include <string>
#include <format>
#include <iostream>

#include "Session.h"

namespace Session {

void TlsSession::addField(const std::string& field_name, std::string field_value) noexcept {
    if (field_name == "sni") {
        _sni = std::move(field_value);
    }
    else if (field_name == "common-name") {
        _common_name = std::move(field_value);
    }
    else if (field_name == "subject-alternative-name") {
        _subject_alternative_name = std::move(field_value);
    }
    else if (field_name == "fingerprint") {
        _certificate_fingerprint = std::move(field_value);
    }
}

void TlsSession::print() const noexcept {
	std::cout << ">>>>>>>>> TLS Session Content:\n";
	std::cout << std::format("sni: {}\n", _sni);
	std::cout << std::format("common name: {}\n", _common_name);
	std::cout << std::format("subject alter: {}\n", _subject_alternative_name);
	std::cout << std::format("certificate: {}\n", _certificate_fingerprint);
	std::cout << "<<<<<<<<< TLS Session Content\n";

	std::flush(std::cout);
}

void HttpSession::addField(const std::string& field_name, std::string field_value) noexcept {
    if (field_name == "method") {
        _method = std::move(field_value);
    }
    else if (field_name == "uri") {
        _uri = std::move(field_value);
    }
    else if (field_name == "version") {
        _version = std::move(field_value);
    }
    else if (field_name == "host") {
        _host = std::move(field_value);
    }
    else if (field_name == "user-agent") {
        _useragent = std::move(field_value);
    }
    else if (field_name == "content-length") {
        _contentlength = std::move(field_value);
    }
    else if (field_name == "cookie") {
        _cookie = std::move(field_value);
    }
}

void HttpSession::print() const noexcept {
    std::cout << ">>>>>>>>> HTTP Session Content:\n";
    std::cout << std::format("method: {}\n", _method);
    std::cout << std::format("uri: {}\n", _uri);
    std::cout << std::format("version: {}\n", _version);
    std::cout << std::format("host: {}\n", _host);
    std::cout << std::format("user-agent: {}\n", _useragent);
    std::cout << std::format("content-length: {}\n", _contentlength);
    std::cout << std::format("cookie: {}\n", _cookie);
	std::cout << "<<<<<<<<< HTTP Session Content\n";
}

} // namespace Session