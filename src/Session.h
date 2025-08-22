#pragma once

#include <cinttypes>

#include <string>

namespace Session {

enum class LAYER4_PROTOCOLS : std::uint8_t {
  TCP = 0x0000,
  UDP = 0x0001
};

struct SessionKey {
  std::uint32_t ip1;
  std::uint32_t ip2;
  std::uint16_t port1;
  std::uint16_t port2;
  LAYER4_PROTOCOLS l4proto;

  bool operator<(const SessionKey &other) const noexcept;
};

class SessionBase {
public:
  virtual ~SessionBase() = default;
  virtual void print() const noexcept = 0;
};

class TlsSession final : public SessionBase {
public:
  TlsSession() = default;

  void print() const noexcept override;
  void addField(const std::string& field_name, std::string field_value) noexcept;

private:
  std::string _sni;
  std::string _common_name;
  std::string _subject_alternative_name;
  std::string _certificate_fingerprint;
};

class HttpSession final : public SessionBase {
public:
  HttpSession() = default;

  void print() const noexcept override;
  void addField(const std::string& field_name, std::string field_value) noexcept;

private:
  std::string _method;
  std::string _uri;
  std::string _version;
  std::string _host;
  std::string _useragent;
  std::string _contentlength;
  std::string _cookie;
};

} // namespace Session