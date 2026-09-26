#include "catapult/reference_policies.hpp"

#include <arpa/inet.h>

#include <cstring>
#include <stdexcept>
#include <string>

namespace catapult {

namespace {

// Parse "addr" or "addr/prefix" into an IpAllowlistEntry. Returns false
// on any structural or numeric failure; the caller turns that into a
// user-visible `std::invalid_argument`.
bool parseEntry(std::string_view text, IpAllowlistEntry& out) noexcept {
  std::string addr_s;
  int prefix = -1;
  auto slash = text.find('/');
  if (slash == std::string_view::npos) {
    addr_s.assign(text.begin(), text.end());
  } else {
    addr_s.assign(text.begin(), text.begin() + slash);
    auto tail = text.substr(slash + 1);
    if (tail.empty() || tail.size() > 3) return false;
    prefix = 0;
    for (char c : tail) {
      if (c < '0' || c > '9') return false;
      prefix = prefix * 10 + (c - '0');
      if (prefix > 128) return false;
    }
  }

  // Try IPv4 first.
  in_addr v4{};
  if (inet_pton(AF_INET, addr_s.c_str(), &v4) == 1) {
    out.is_v6 = false;
    std::memset(out.bytes, 0, sizeof(out.bytes));
    std::memcpy(out.bytes, &v4, 4);
    if (prefix < 0) prefix = 32;
    if (prefix > 32) return false;
    out.prefix_bits = static_cast<uint8_t>(prefix);
    return true;
  }

  in6_addr v6{};
  if (inet_pton(AF_INET6, addr_s.c_str(), &v6) == 1) {
    out.is_v6 = true;
    std::memcpy(out.bytes, &v6, 16);
    if (prefix < 0) prefix = 128;
    if (prefix > 128) return false;
    out.prefix_bits = static_cast<uint8_t>(prefix);
    return true;
  }

  return false;
}

// Match `addr_bytes` (raw network-order address, 4 or 16 bytes) against
// a parsed entry's masked prefix.
bool matchesEntry(const IpAllowlistEntry& e, bool query_is_v6,
                  const uint8_t* addr_bytes) noexcept {
  if (e.is_v6 != query_is_v6) return false;
  size_t total_bits = query_is_v6 ? 128 : 32;
  if (e.prefix_bits > total_bits) return false;
  size_t full_bytes = e.prefix_bits / 8;
  size_t rem_bits = e.prefix_bits % 8;
  if (full_bytes > 0 && std::memcmp(e.bytes, addr_bytes, full_bytes) != 0) {
    return false;
  }
  if (rem_bits == 0) return true;
  uint8_t mask = static_cast<uint8_t>(0xFFu << (8 - rem_bits));
  return (e.bytes[full_bytes] & mask) == (addr_bytes[full_bytes] & mask);
}

bool ipMatches(const std::vector<IpAllowlistEntry>& entries,
               std::string_view ip) noexcept {
  if (ip.empty() || ip.size() > 45) return false;
  // inet_pton wants NUL-terminated input.
  char buf[46] = {};
  std::memcpy(buf, ip.data(), ip.size());

  in_addr v4{};
  if (inet_pton(AF_INET, buf, &v4) == 1) {
    uint8_t bytes[4];
    std::memcpy(bytes, &v4, 4);
    for (const auto& e : entries) {
      if (matchesEntry(e, false, bytes)) return true;
    }
    return false;
  }
  in6_addr v6{};
  if (inet_pton(AF_INET6, buf, &v6) == 1) {
    uint8_t bytes[16];
    std::memcpy(bytes, &v6, 16);
    for (const auto& e : entries) {
      if (matchesEntry(e, true, bytes)) return true;
    }
    return false;
  }
  return false;
}

}  // namespace

// --------------------------------------------------------------------------
// IpAllowlistPolicy
// --------------------------------------------------------------------------

IpAllowlistPolicy::IpAllowlistPolicy(const std::vector<std::string>& entries) {
  entries_.reserve(entries.size());
  for (const auto& e : entries) {
    IpAllowlistEntry parsed;
    if (!parseEntry(e, parsed)) {
      throw std::invalid_argument("IpAllowlistPolicy: invalid entry: " + e);
    }
    entries_.push_back(parsed);
  }
}

bool IpAllowlistPolicy::contains(std::string_view ip) const noexcept {
  return ipMatches(entries_, ip);
}

bool IpAllowlistPolicy::matches(const PolicyContext& ctx) const noexcept {
  if (!ctx.client_ip.has_value()) return false;
  return ipMatches(entries_, *ctx.client_ip);
}

bool IpAllowlistPolicy::acceptProofOfPossession(const CatProofOfPossession&,
                                                const PolicyContext& ctx) {
  return matches(ctx);
}

bool IpAllowlistPolicy::acceptDpopBinding(const CatDpopSettings&,
                                          const PolicyContext& ctx) {
  return matches(ctx);
}

bool IpAllowlistPolicy::acceptRequestDirective(std::string_view,
                                               const CatRequestDirective&,
                                               const PolicyContext& ctx) {
  return matches(ctx);
}

bool IpAllowlistPolicy::acceptGeoIso3166(const std::vector<std::string>&,
                                         const PolicyContext& ctx) {
  return matches(ctx);
}

bool IpAllowlistPolicy::acceptGeohash(const GeohashClaimValue&,
                                      const PolicyContext& ctx) {
  return matches(ctx);
}

bool IpAllowlistPolicy::acceptGeoAltitude(const GeoAltitude&,
                                          const PolicyContext& ctx) {
  return matches(ctx);
}

// --------------------------------------------------------------------------
// DpopBindingPolicy
// --------------------------------------------------------------------------

bool DpopBindingPolicy::acceptDpopBinding(const CatDpopSettings& wire,
                                          const PolicyContext& ctx) {
  if (ctx.dpop_proof == nullptr) return false;
  if (overlay_target_ != nullptr) {
    std::lock_guard<std::mutex> lock(overlay_mu_);
    overlay_target_->overlayCatDpopSettings(wire);
  }
  return true;
}

}  // namespace catapult
