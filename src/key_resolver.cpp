#include "catapult/key_resolver.hpp"

#include "catapult/crypto.hpp"

namespace catapult {

void StaticKeyResolver::add(
    std::string kid, int64_t alg,
    std::shared_ptr<const CryptographicAlgorithm> algorithm) {
  if (!algorithm) {
    throw MissingKeyError("null algorithm supplied to StaticKeyResolver::add");
  }
  entries_[Key{std::move(kid), alg}] = std::move(algorithm);
}

const CryptographicAlgorithm& StaticKeyResolver::resolve(std::string_view kid,
                                                         int64_t alg) const {
  auto it = entries_.find(Key{std::string(kid), alg});
  if (it == entries_.end()) {
    // Deliberately do not echo the caller-provided kid back into the error
    // string: kids can carry attacker-controlled content and logging them
    // verbatim through validation-error surfaces is a foot-gun. The alg
    // is a small integer identifier and is safe to include.
    throw MissingKeyError("no verifier registered for the presented alg " +
                          std::to_string(alg));
  }
  return *it->second;
}

std::size_t StaticKeyResolver::size() const noexcept { return entries_.size(); }

}  // namespace catapult
