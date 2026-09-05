/**
 * @file dpop.cpp
 * @brief Tests for CWT-encoded DPoP proof round-trip and Sig_structure
 *        compliance (H-04).
 *
 * The core assertions here are:
 *  - A proof signed by DpopKeyPair verifies against the same key pair.
 *  - The signing input is a COSE_Sign1 Sig_structure (RFC 8152 §4.4), so
 *    tampering with the protected header (alg_id or cose_key) invalidates
 *    the signature — this is the security fix at the heart of H-04.
 *  - Serialize / deserialize is byte-preserving for the fields that matter:
 *    header (alg_id, cose_key), payload (actx, iat, jti), signature.
 */

#include <cbor.h>
#include <doctest/doctest.h>

#include <memory>
#include <string>

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/dpop.hpp"
#include "catapult/moqt_claims.hpp"

using namespace catapult;

namespace {

std::unique_ptr<DpopKeyPair> makeEs256KeyPair() {
  auto alg = std::make_unique<Es256Algorithm>();
  return std::make_unique<DpopKeyPair>(std::move(alg));
}

}  // namespace

TEST_SUITE("DPoP CWT wire format") {
  TEST_CASE("Signed proof round-trips through serialize/deserialize") {
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns.example", "track-1",
        "relay.example:4433", std::string{"jti-abc"});

    auto wire = proof.serialize();
    auto decoded = DpopProof::deserialize(wire);

    CHECK(decoded.encoding() == DpopEncoding::CWT);
    CHECK(decoded.get_header().alg_id == keys->get_algorithm_id());
    CHECK(decoded.get_header().cose_key == keys->get_cose_key());
    CHECK(decoded.get_payload().actx.type == "moqt");
    CHECK(decoded.get_payload().actx.action == moqt_actions::PUBLISH);
    CHECK(decoded.get_payload().actx.tns == "ns.example");
    CHECK(decoded.get_payload().actx.tn == "track-1");
    CHECK(decoded.get_payload().jti.has_value());
    CHECK(*decoded.get_payload().jti == "jti-abc");
  }

  TEST_CASE("Verify uses COSE_Sign1 Sig_structure — signature verifies") {
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::SUBSCRIBE, "ns", "trk", "relay:4433",
        std::string{"jti-1"});

    // Verifier uses the same algorithm the signer used.
    CHECK(proof.verify_signature(keys->get_algorithm()));

    // A round-tripped copy must also verify — the Sig_structure inputs on
    // both sides depend on the protected-header bytes and the payload bytes
    // being reconstructed byte-identically.
    auto wire = proof.serialize();
    auto decoded = DpopProof::deserialize(wire);
    CHECK(decoded.verify_signature(keys->get_algorithm()));
  }

  TEST_CASE(
      "Signing input is a COSE_Sign1 Sig_structure with context 'Signature1'") {
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti"});
    auto sig_input = proof.create_signing_input();

    cbor_load_result result;
    cbor_item_t* item = cbor_load(sig_input.data(), sig_input.size(), &result);
    REQUIRE(result.error.code == CBOR_ERR_NONE);
    REQUIRE(item != nullptr);
    REQUIRE(cbor_isa_array(item));
    REQUIRE(cbor_array_size(item) == 4);

    // Element 0 must be the text string "Signature1" — otherwise a signer
    // could reuse another COSE context and cause cross-context tag confusion.
    cbor_item_t* context = cbor_array_get(item, 0);
    REQUIRE(context != nullptr);
    REQUIRE(cbor_isa_string(context));
    std::string ctx(reinterpret_cast<const char*>(cbor_string_handle(context)),
                    cbor_string_length(context));
    CHECK(ctx == "Signature1");
    cbor_decref(&context);
    cbor_decref(&item);
  }

  TEST_CASE(
      "Tampering with the protected header invalidates the signature") {
    // The heart of H-04: prior to this fix the payload alone was signed, so
    // an attacker could swap `alg_id` or `cose_key` in the protected header
    // without affecting verification. The Sig_structure fix binds both to
    // the signature — a mutated protected header MUST reject.
    auto signer_keys = makeEs256KeyPair();
    auto proof = signer_keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti"});
    auto wire = proof.serialize();
    auto decoded = DpopProof::deserialize(wire);
    REQUIRE(decoded.verify_signature(signer_keys->get_algorithm()));

    // Construct a proof that reuses the original signature and payload but
    // advertises a *different* signer's cose_key in the protected header.
    // With the correct Sig_structure inputs, the signer's own algorithm
    // must reject this tampered proof.
    auto other_keys = makeEs256KeyPair();
    DpopHeader tampered_header = decoded.get_header();
    tampered_header.cose_key = other_keys->get_cose_key();
    DpopProof tampered{tampered_header, decoded.get_payload(),
                       decoded.get_signature(), DpopEncoding::CWT};
    CHECK_FALSE(tampered.verify_signature(signer_keys->get_algorithm()));
  }

  TEST_CASE("DpopProofValidator accepts a well-formed proof") {
    auto keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-vp-1"});

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    DpopProofValidator validator(settings);
    validator.set_cwt_verifier(&keys->get_algorithm());

    CHECK(validator.validate_proof(proof, moqt_actions::PUBLISH, expected_uri,
                                   keys->get_public_key_thumbprint()));
  }

  TEST_CASE(
      "DpopProofValidator rejects a proof signed by a different key") {
    auto real_keys = makeEs256KeyPair();
    auto imposter_keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    auto proof = real_keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-vp-2"});

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    DpopProofValidator validator(settings);
    // Bind validator to the wrong key.
    validator.set_cwt_verifier(&imposter_keys->get_algorithm());

    CHECK_FALSE(validator.validate_proof(proof, moqt_actions::PUBLISH,
                                         expected_uri,
                                         real_keys->get_public_key_thumbprint()));
  }
}
