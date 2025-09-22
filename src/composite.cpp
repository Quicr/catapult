#include "catapult/composite.hpp"
#include "catapult/token.hpp"
#include "catapult/error.hpp"
#include "catapult/composite_impl.hpp"

#include <chrono>
#include <memory>
#include <ranges>
#include <algorithm>
#include <utility>

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

std::unique_ptr<OrClaim> createOrComposite(const std::vector<ClaimSet>& claimSets, bool usePool) {
  // Create composite using standard allocation - pool optimization applied internally
  auto composite = std::make_unique<OrClaim>(usePool);
  for (const auto& claimSet : claimSets) {
    composite->addClaimSet(claimSet);
  }
  return composite;
}

std::unique_ptr<NorClaim> createNorComposite(const std::vector<ClaimSet>& claimSets, bool usePool) {
  // Create composite using standard allocation - pool optimization applied internally
  auto composite = std::make_unique<NorClaim>(usePool);
  for (const auto& claimSet : claimSets) {
    composite->addClaimSet(claimSet);
  }
  return composite;
}

std::unique_ptr<AndClaim> createAndComposite(const std::vector<ClaimSet>& claimSets, bool usePool) {
  // Create composite using standard allocation - pool optimization applied internally
  auto composite = std::make_unique<AndClaim>(usePool);
  for (const auto& claimSet : claimSets) {
    composite->addClaimSet(claimSet);
  }
  return composite;
}

std::unique_ptr<OrClaim> createOrFromTokens(const std::vector<CatToken>& tokens, bool usePool) {
  // Create composite using standard allocation - pool optimization applied internally
  auto composite = std::make_unique<OrClaim>(usePool);
  for (const auto& token : tokens) {
    composite->addToken(token);
  }
  return composite;
}

std::unique_ptr<NorClaim> createNorFromTokens(const std::vector<CatToken>& tokens, bool usePool) {
  // Create composite using standard allocation - pool optimization applied internally
  auto composite = std::make_unique<NorClaim>(usePool);
  for (const auto& token : tokens) {
    composite->addToken(token);
  }
  return composite;
}

std::unique_ptr<AndClaim> createAndFromTokens(const std::vector<CatToken>& tokens, bool usePool) {
  // Create composite using standard allocation - pool optimization applied internally
  auto composite = std::make_unique<AndClaim>(usePool);
  for (const auto& token : tokens) {
    composite->addToken(token);
  }
  return composite;
}

} // namespace composite_utils

// Template instantiations will be handled by including the implementation header
// when CatTokenValidator is fully defined

} // namespace catapult