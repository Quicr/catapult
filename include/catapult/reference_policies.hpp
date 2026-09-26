/**
 * @file reference_policies.hpp
 * @brief Reference `AuthorizationPolicyHook` implementations shipped with
 *        the catapult library.
 *
 * `authorization_policy.hpp` defines the seam; this header ships two
 * concrete building blocks that are useful in production integrations
 * and give operators a starting point rather than forcing them to write
 * the wiring from scratch.
 *
 *   - `IpAllowlistPolicy` — accepts the request iff `ctx.client_ip`
 *     parses to an address inside one of the operator-supplied
 *     IPv4/IPv6 CIDR blocks (or matches a bare-host entry). All other
 *     `accept*()` hooks are pass-through: this policy composes with
 *     other reference policies via `ChainedPolicy` when a deployment
 *     wants more than one dimension of enforcement.
 *
 *   - `DpopBindingPolicy` — accepts the request iff a validated DPoP
 *     proof is present on the `PolicyContext`, and (optionally)
 *     overlays the token's on-wire `catdpop` settings onto a
 *     `DpopValidationSettings` instance so the token can *tighten* the
 *     acceptance window / turn on replay-tracking without ever being
 *     able to widen either. Every other accept*() surface is
 *     pass-through.
 *
 * Both classes are `final` and internally use only immutable state
 * after construction — safe to share across every worker thread of a
 * relay's dispatch pool without external synchronisation.
 *
 * @note Neither class fully replaces a hand-rolled deployment-specific
 *   policy. They are the pieces every deployment needs; the hard part
 *   — a block-list feed, a geo lookup, a rich `catif`/`catr` policy —
 *   remains operator responsibility.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "authorization_policy.hpp"
#include "dpop.hpp"

namespace catapult {

// --------------------------------------------------------------------------
// IP allowlist
// --------------------------------------------------------------------------

/**
 * @brief Parsed CIDR entry. Public so callers who want to introspect an
 *        `IpAllowlistPolicy`'s configured entries (metrics, admin
 *        endpoints) can do so without stringifying and re-parsing.
 */
struct IpAllowlistEntry {
  bool is_v6 = false;
  uint8_t bytes[16] = {};   ///< network-order prefix bytes; unused bytes zero
  uint8_t prefix_bits = 0;  ///< 0..32 for v4, 0..128 for v6
};

/**
 * @brief Reference policy that admits a request only when
 *        `ctx.client_ip` falls inside one of the configured
 *        IPv4/IPv6 CIDR blocks (or matches a bare-host entry).
 *
 * ## Wire format for entries
 *
 * Each entry passed to the constructor is one of:
 *   - IPv4 address (`10.1.2.3`) — treated as `/32`.
 *   - IPv4 CIDR (`10.0.0.0/8`).
 *   - IPv6 address (`2001:db8::1`) — treated as `/128`.
 *   - IPv6 CIDR (`2001:db8::/32`).
 *
 * Parsing uses `inet_pton`; any entry that fails to parse causes the
 * constructor to throw `std::invalid_argument`. This is a
 * configuration-time failure, not a per-request one.
 *
 * ## Contract on the accept*() methods
 *
 * Every `accept*()` method — including `acceptDpopBinding` — is scoped
 * by the allowlist. The policy models a *global request filter*: a
 * request whose `client_ip` is not on the allowlist is rejected no
 * matter which enforcement-gated claim happens to be present. Callers
 * layer additional requirements (e.g. "and a DPoP proof must be
 * presented") by composing with another policy via `ChainedPolicy`,
 * not by expecting this policy to carve out particular claims.
 *
 * ## `client_ip` handling
 *
 * If `ctx.client_ip` is `std::nullopt`, every `accept*()` method on
 * this policy returns `false`: absence of an IP under this policy is
 * a policy failure, not a permissive default. Callers who want to
 * short-circuit missing IPs earlier should set
 * `RequiredPolicyContextFields::client_ip = true` on the validator so
 * the missing field surfaces as `MissingRequiredClaimError`.
 */
class IpAllowlistPolicy final : public AuthorizationPolicyHook {
 public:
  /**
   * @brief Build the policy from a list of textual IPv4/IPv6 addresses
   *        or CIDR blocks. Throws `std::invalid_argument` on any
   *        malformed entry.
   */
  explicit IpAllowlistPolicy(const std::vector<std::string>& entries);

  /**
   * @brief Test whether an address string (as it would appear on
   *        `PolicyContext::client_ip`) is inside the allowlist.
   *        Useful for host-side pre-filtering that wants to short-
   *        circuit before invoking the full validator.
   */
  [[nodiscard]] bool contains(std::string_view ip) const noexcept;

  /**
   * @brief Number of parsed entries. Exposed for host-side metrics /
   *        introspection.
   */
  [[nodiscard]] size_t size() const noexcept { return entries_.size(); }

  bool acceptProofOfPossession(const CatProofOfPossession&,
                               const PolicyContext& ctx) override;
  bool acceptDpopBinding(const CatDpopSettings&,
                         const PolicyContext& ctx) override;
  bool acceptRequestDirective(std::string_view, const CatRequestDirective&,
                              const PolicyContext& ctx) override;
  bool acceptGeoIso3166(const std::vector<std::string>&,
                        const PolicyContext& ctx) override;
  bool acceptGeohash(const GeohashClaimValue&,
                     const PolicyContext& ctx) override;
  bool acceptGeoAltitude(const GeoAltitude&, const PolicyContext& ctx) override;

 private:
  [[nodiscard]] bool matches(const PolicyContext& ctx) const noexcept;

  std::vector<IpAllowlistEntry> entries_;
};

// --------------------------------------------------------------------------
// DPoP binding
// --------------------------------------------------------------------------

/**
 * @brief Reference policy that ties a request's `catdpop` claim to the
 *        presence of a validated DPoP proof on `PolicyContext`, and
 *        optionally overlays the token's on-wire settings onto an
 *        operator-owned `DpopValidationSettings`.
 *
 * ## Overlay contract
 *
 * If constructed with a non-null `DpopValidationSettings*`,
 * `acceptDpopBinding` calls
 * `DpopValidationSettings::overlayCatDpopSettings(wire_settings)` on
 * that instance. The overlay is one-way by design (see the doc
 * comment on `overlayCatDpopSettings` in `dpop.hpp`): the token can
 * tighten the window and *enable* replay-tracking, but never widen or
 * disable.
 *
 * If constructed without an overlay target, the policy still requires
 * a `dpop_proof` on the context but leaves the DPoP validator's
 * configuration untouched.
 *
 * ## Concurrency
 *
 * When an overlay target is supplied, calls to `acceptDpopBinding`
 * serialise on an internal mutex. This is a per-token overlay: a
 * concurrent stream of requests carrying differently-tightened
 * `catdpop` settings must not race on the shared settings object. If
 * the overlay target is null, this policy is entirely lock-free.
 *
 * All other `accept*()` methods are unconditionally accepting; compose
 * with an `IpAllowlistPolicy` (or a bespoke policy) for orthogonal
 * enforcement.
 */
class DpopBindingPolicy final : public AuthorizationPolicyHook {
 public:
  /**
   * @brief Build a binding policy that requires `ctx.dpop_proof` to be
   *        non-null. `overlay_target`, when non-null, receives the
   *        token's on-wire `catdpop` via
   *        `DpopValidationSettings::overlayCatDpopSettings` on every
   *        `acceptDpopBinding` call.
   *
   * `overlay_target` is a non-owning pointer; it must outlive this
   * policy.
   */
  explicit DpopBindingPolicy(
      DpopValidationSettings* overlay_target = nullptr) noexcept
      : overlay_target_(overlay_target) {}

  bool acceptProofOfPossession(const CatProofOfPossession&,
                               const PolicyContext&) override {
    return true;
  }
  bool acceptDpopBinding(const CatDpopSettings& wire,
                         const PolicyContext& ctx) override;
  bool acceptRequestDirective(std::string_view, const CatRequestDirective&,
                              const PolicyContext&) override {
    return true;
  }
  bool acceptGeoIso3166(const std::vector<std::string>&,
                        const PolicyContext&) override {
    return true;
  }
  bool acceptGeohash(const GeohashClaimValue&, const PolicyContext&) override {
    return true;
  }
  bool acceptGeoAltitude(const GeoAltitude&, const PolicyContext&) override {
    return true;
  }

 private:
  DpopValidationSettings* overlay_target_;
  std::mutex overlay_mu_;
};

// --------------------------------------------------------------------------
// Composition
// --------------------------------------------------------------------------

/**
 * @brief Compose two or more `AuthorizationPolicyHook` instances with
 *        AND-semantics: every `accept*()` returns `true` only if every
 *        composed policy returns `true`, evaluated left-to-right and
 *        short-circuiting on the first `false`.
 *
 * The chain does not own the composed policies. Every referenced hook
 * must outlive the `ChainedPolicy` that wraps it, and each of the
 * composed hooks must itself satisfy the concurrent-invocation
 * contract on `AuthorizationPolicyHook`.
 */
class ChainedPolicy final : public AuthorizationPolicyHook {
 public:
  explicit ChainedPolicy(std::vector<AuthorizationPolicyHook*> chain) noexcept
      : chain_(std::move(chain)) {}

  bool acceptProofOfPossession(const CatProofOfPossession& por,
                               const PolicyContext& ctx) override {
    for (auto* p : chain_)
      if (!p->acceptProofOfPossession(por, ctx)) return false;
    return true;
  }
  bool acceptDpopBinding(const CatDpopSettings& s,
                         const PolicyContext& ctx) override {
    for (auto* p : chain_)
      if (!p->acceptDpopBinding(s, ctx)) return false;
    return true;
  }
  bool acceptRequestDirective(std::string_view name,
                              const CatRequestDirective& d,
                              const PolicyContext& ctx) override {
    for (auto* p : chain_)
      if (!p->acceptRequestDirective(name, d, ctx)) return false;
    return true;
  }
  bool acceptGeoIso3166(const std::vector<std::string>& codes,
                        const PolicyContext& ctx) override {
    for (auto* p : chain_)
      if (!p->acceptGeoIso3166(codes, ctx)) return false;
    return true;
  }
  bool acceptGeohash(const GeohashClaimValue& v,
                     const PolicyContext& ctx) override {
    for (auto* p : chain_)
      if (!p->acceptGeohash(v, ctx)) return false;
    return true;
  }
  bool acceptGeoAltitude(const GeoAltitude& v,
                         const PolicyContext& ctx) override {
    for (auto* p : chain_)
      if (!p->acceptGeoAltitude(v, ctx)) return false;
    return true;
  }

 private:
  std::vector<AuthorizationPolicyHook*> chain_;
};

}  // namespace catapult
