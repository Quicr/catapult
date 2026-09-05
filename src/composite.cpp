#include "catapult/composite.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <ranges>
#include <utility>

#include "catapult/composite_impl.hpp"
#include "catapult/error.hpp"
#include "catapult/logging.hpp"
#include "catapult/token.hpp"

namespace catapult {

// ClaimSet constructor implementations
ClaimSet::ClaimSet(const CatToken& t) : token(std::make_unique<CatToken>(t)) {}

// ClaimSet copy constructor
ClaimSet::ClaimSet(const ClaimSet& other) {
  if (other.token) {
    token = std::make_unique<CatToken>(*other.token);
  }
  if (other.orComposite) {
    orComposite = std::make_unique<OrClaim>(*other.orComposite);
  }
  if (other.andComposite) {
    andComposite = std::make_unique<AndClaim>(*other.andComposite);
  }
  if (other.norComposite) {
    norComposite = std::make_unique<NorClaim>(*other.norComposite);
  }
}

// ClaimSet assignment operator using copy-and-swap idiom
ClaimSet& ClaimSet::operator=(ClaimSet other) noexcept {
  swap(other);
  return *this;
}

// ClaimSet swap function for copy-and-swap idiom
void ClaimSet::swap(ClaimSet& other) noexcept {
  using std::swap;
  swap(token, other.token);
  swap(orComposite, other.orComposite);
  swap(andComposite, other.andComposite);
  swap(norComposite, other.norComposite);
}

// CompositeClaims copy constructor
CompositeClaims::CompositeClaims(const CompositeClaims& other) {
  if (other.orClaim.has_value()) {
    orClaim = std::make_unique<OrClaim>(*other.orClaim.value());
  }
  if (other.norClaim.has_value()) {
    norClaim = std::make_unique<NorClaim>(*other.norClaim.value());
  }
  if (other.andClaim.has_value()) {
    andClaim = std::make_unique<AndClaim>(*other.andClaim.value());
  }
}

// CompositeClaims assignment operator
CompositeClaims& CompositeClaims::operator=(const CompositeClaims& other) {
  if (this != &other) {
    orClaim.reset();
    norClaim.reset();
    andClaim.reset();

    if (other.orClaim.has_value()) {
      orClaim = std::make_unique<OrClaim>(*other.orClaim.value());
    }
    if (other.norClaim.has_value()) {
      norClaim = std::make_unique<NorClaim>(*other.norClaim.value());
    }
    if (other.andClaim.has_value()) {
      andClaim = std::make_unique<AndClaim>(*other.andClaim.value());
    }
  }
  return *this;
}

bool CompositeClaims::hasComposites() const {
  return orClaim.has_value() || norClaim.has_value() || andClaim.has_value();
}

// Composite utility functions
namespace composite_utils {

// CTA-5007-B remediation (C-06): the pool-backed paths returned pooled storage
// inside a default-deleter std::unique_ptr, which is undefined behavior on
// destruction (the pool owns the memory, not the global allocator). Until the
// pool ownership model is rewritten in Phase 3 (task #24 / [[composite-pool-
// rewrite]]), the `usePool` argument is intentionally ignored — every factory
// unconditionally uses standard allocation. Log a warning so callers requesting
// the pool path notice the downgrade instead of silently paying no perf cost.
namespace {
inline void warn_if_pool_requested(bool usePool, const char* which) {
  if (usePool) {
    CAT_LOG_WARN(
        "{}: pool-backed allocation requested but is disabled (C-06 fix); "
        "using standard allocation. See docs/security/SECURITY.md.",
        which);
  }
}
}  // namespace

std::unique_ptr<OrClaim> createOrComposite(
    const std::vector<ClaimSet>& claimSets, bool usePool) {
  warn_if_pool_requested(usePool, "createOrComposite");
  auto composite = std::make_unique<OrClaim>();
  for (const auto& claimSet : claimSets) {
    composite->addClaimSet(claimSet);
  }
  return composite;
}

std::unique_ptr<NorClaim> createNorComposite(
    const std::vector<ClaimSet>& claimSets, bool usePool) {
  warn_if_pool_requested(usePool, "createNorComposite");
  auto composite = std::make_unique<NorClaim>();
  for (const auto& claimSet : claimSets) {
    composite->addClaimSet(claimSet);
  }
  return composite;
}

std::unique_ptr<AndClaim> createAndComposite(
    const std::vector<ClaimSet>& claimSets, bool usePool) {
  warn_if_pool_requested(usePool, "createAndComposite");
  auto composite = std::make_unique<AndClaim>();
  for (const auto& claimSet : claimSets) {
    composite->addClaimSet(claimSet);
  }
  return composite;
}

std::unique_ptr<OrClaim> createOrFromTokens(const std::vector<CatToken>& tokens,
                                            bool usePool) {
  warn_if_pool_requested(usePool, "createOrFromTokens");
  auto composite = std::make_unique<OrClaim>();
  for (const auto& token : tokens) {
    composite->addToken(token);
  }
  return composite;
}

std::unique_ptr<NorClaim> createNorFromTokens(
    const std::vector<CatToken>& tokens, bool usePool) {
  warn_if_pool_requested(usePool, "createNorFromTokens");
  auto composite = std::make_unique<NorClaim>();
  for (const auto& token : tokens) {
    composite->addToken(token);
  }
  return composite;
}

std::unique_ptr<AndClaim> createAndFromTokens(
    const std::vector<CatToken>& tokens, bool usePool) {
  warn_if_pool_requested(usePool, "createAndFromTokens");
  auto composite = std::make_unique<AndClaim>();
  for (const auto& token : tokens) {
    composite->addToken(token);
  }
  return composite;
}

}  // namespace composite_utils

// Template instantiations will be handled by including the implementation
// header when CatTokenValidator is fully defined

}  // namespace catapult