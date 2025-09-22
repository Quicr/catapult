/**
 * @file cat_composite_impl.hpp  
 * @brief Template method implementations for composite claims
 */

#pragma once

namespace catapult {


// Template method definition for TypedCompositeClaim
template<CompositeOperator Op>
requires (is_valid_operator<Op>())
template<typename Validator>
bool TypedCompositeClaim<Op>::evaluateClaimSet(const ClaimSet& claimSet, const Validator& validator) const {
  if (claimSet.hasToken()) {
    try {
      validator.validate(*claimSet.token);
      return true;
    } catch (const CatError&) {
      return false;
    }
  } else if (claimSet.hasComposite()) {
    if (claimSet.orComposite) {
      return claimSet.orComposite->evaluate(validator);
    } else if (claimSet.andComposite) {
      return claimSet.andComposite->evaluate(validator);
    } else if (claimSet.norComposite) {
      return claimSet.norComposite->evaluate(validator);
    }
  }
  return false;
}

// Template method definition for CompositeClaims
template<TokenValidator Validator>
bool CompositeClaims::validateAll(const Validator& validator) const {
  if (orClaim && !(*orClaim)->evaluate(validator)) {
    return false;
  }
  if (norClaim && !(*norClaim)->evaluate(validator)) {
    return false;
  }
  if (andClaim && !(*andClaim)->evaluate(validator)) {
    return false;
  }
  return true;
}

} // namespace catapult