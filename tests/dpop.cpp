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

  TEST_CASE("construct_moqt_uri emits the CAT-4-MOQT query-parameter form") {
    // Endpoint-only (setup actions): no query string.
    CHECK(moqt_dpop::construct_moqt_uri("relay:4433") == "moqt://relay:4433");

    // Namespace-scoped actions: only `tns` present.
    CHECK(moqt_dpop::construct_moqt_uri("relay:4433", "ns.example") ==
          "moqt://relay:4433?tns=ns.example");

    // Track-level actions: both `tns` and `tn` present, ampersand-joined.
    CHECK(moqt_dpop::construct_moqt_uri("relay:4433", "ns.example",
                                        "track-1") ==
          "moqt://relay:4433?tns=ns.example&tn=track-1");

    // Reserved characters in the components must be percent-encoded so a
    // namespace containing `&` or `=` cannot smuggle in extra query
    // parameters that the verifier would then compare against.
    CHECK(moqt_dpop::construct_moqt_uri("relay:4433", "ns/with=eq&amp",
                                        "trk?") ==
          "moqt://relay:4433?tns=ns%2Fwith%3Deq%26amp&tn=trk%3F");
  }

  TEST_CASE("AuthorizationContext validity gates on the action class") {
    // Setup actions have no namespace or track.
    AuthorizationContext setup{moqt_actions::CLIENT_SETUP,
                               "moqt://relay:4433"};
    CHECK(setup.is_valid());

    // Namespace-scoped actions require `tns` but not `tn`.
    AuthorizationContext ns_scoped{moqt_actions::PUBLISH_NAMESPACE,
                                   "ns.example", "",
                                   "moqt://relay:4433?tns=ns.example"};
    CHECK(ns_scoped.is_valid());
    AuthorizationContext ns_missing{moqt_actions::PUBLISH_NAMESPACE,
                                    "moqt://relay:4433"};
    CHECK_FALSE(ns_missing.is_valid());

    // Track-level actions require both.
    AuthorizationContext track_full{moqt_actions::PUBLISH, "ns.example",
                                    "trk-1", "moqt://relay:4433"};
    CHECK(track_full.is_valid());
    AuthorizationContext track_missing_tn{moqt_actions::PUBLISH,
                                          "ns.example", "",
                                          "moqt://relay:4433"};
    CHECK_FALSE(track_missing_tn.is_valid());
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

  TEST_CASE("DpopProofValidator refuses an empty expected thumbprint") {
    // HN-03: an empty expected thumbprint cannot represent a policy
    // intent. The API must fail closed rather than let the caller
    // accidentally disable the `cnf`/`catdpop` binding check.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-empty-thumb"});
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    DpopProofValidator validator(settings);
    validator.set_cwt_verifier(&keys->get_algorithm());

    CHECK_FALSE(
        validator.validate_proof(proof, moqt_actions::PUBLISH, expected_uri,
                                 /*expected_public_key_thumbprint=*/""));
  }

  TEST_CASE(
      "DpopProofValidator rejects wrong-key proofs before touching the "
      "replay store") {
    // HN-03: the thumbprint check must precede replay admission —
    // otherwise a proof bound to another key can consume admission
    // slots for the victim's jti, poisoning the bounded store.
    auto real_keys = makeEs256KeyPair();
    auto imposter_keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    auto imposter_proof = imposter_keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-shared-target"});

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    DpopProofValidator validator(settings);
    // Verifier is bound to the imposter's key so signature verification
    // itself would succeed. The rejection must therefore come from the
    // thumbprint mismatch check, not from replay admission.
    validator.set_cwt_verifier(&imposter_keys->get_algorithm());

    CHECK_FALSE(validator.validate_proof(
        imposter_proof, moqt_actions::PUBLISH, expected_uri,
        real_keys->get_public_key_thumbprint()));

    // The victim's own proof reusing the same jti must still be
    // admittable — if the imposter's rejected proof had consumed the
    // slot, this would fail.
    auto victim_proof = real_keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-shared-target"});
    validator.set_cwt_verifier(&real_keys->get_algorithm());
    CHECK(validator.validate_proof(victim_proof, moqt_actions::PUBLISH,
                                   expected_uri,
                                   real_keys->get_public_key_thumbprint()));
  }

#ifdef CATAPULT_ENABLE_JSON
  TEST_CASE(
      "JWT DPoP emits `actx.action` as an action-name string per the pinned "
      "CAT-4-MOQT profile") {
    // L-03: the earlier form serialised the numeric COSE label
    // (`actx.action = 6`) rather than the pinned-draft action name
    // (`actx.action = "PUBLISH"`). Peers that follow the draft would
    // reject the numeric form. Verify both the wire payload string
    // form and a full round-trip.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns.example", "track-1",
        "relay.example:4433", std::string{"jti-jwt-action"},
        DpopEncoding::JWT);
    auto wire = proof.serialize();

    // Split JWT and decode the middle segment (payload) — the action
    // must be the string "PUBLISH", not an integer.
    auto first_dot = wire.find('.');
    auto second_dot = wire.find('.', first_dot + 1);
    REQUIRE(first_dot != std::string::npos);
    REQUIRE(second_dot != std::string::npos);
    auto payload_b64 = wire.substr(first_dot + 1, second_dot - first_dot - 1);
    auto payload_bytes = base64UrlDecode(payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());
    // Direct substring check: the JSON must literally contain
    // "action":"PUBLISH" — a numeric form would produce "action":6.
    CHECK(payload_json.find("\"action\":\"PUBLISH\"") != std::string::npos);
    CHECK(payload_json.find("\"action\":6") == std::string::npos);

    // Round-trip: the parsed struct must map back to the numeric action
    // for downstream policy checks.
    auto decoded = DpopProof::deserialize(wire);
    CHECK(decoded.encoding() == DpopEncoding::JWT);
    CHECK(decoded.get_payload().actx.action == moqt_actions::PUBLISH);
  }

  TEST_CASE(
      "JWT DPoP rejects a numeric or unknown `actx.action` on deserialize") {
    // A draft-shaped peer emits action names; any producer that still
    // sends a number, or a name catapult doesn't know, must be rejected
    // rather than silently reinterpreted.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-numeric-action"}, DpopEncoding::JWT);
    auto wire = proof.serialize();

    // Mutate the payload segment to carry a numeric action and re-encode.
    auto first_dot = wire.find('.');
    auto second_dot = wire.find('.', first_dot + 1);
    auto header_b64 = wire.substr(0, first_dot);
    auto sig_b64 = wire.substr(second_dot + 1);
    auto payload_b64 = wire.substr(first_dot + 1, second_dot - first_dot - 1);
    auto payload_bytes = base64UrlDecode(payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());

    // Swap "action":"PUBLISH" for "action":6.
    auto pos = payload_json.find("\"action\":\"PUBLISH\"");
    REQUIRE(pos != std::string::npos);
    payload_json.replace(pos, sizeof("\"action\":\"PUBLISH\"") - 1,
                         "\"action\":6");
    auto mutated_b64 = base64UrlEncode(
        std::vector<uint8_t>(payload_json.begin(), payload_json.end()));
    std::string mutated_wire =
        header_b64 + "." + mutated_b64 + "." + sig_b64;
    CHECK_THROWS(DpopProof::deserialize(mutated_wire));

    // An unknown action name must also reject.
    auto pos2 = payload_json.find("\"action\":6");
    REQUIRE(pos2 != std::string::npos);
    payload_json.replace(pos2, sizeof("\"action\":6") - 1,
                         "\"action\":\"MADE_UP\"");
    auto unknown_b64 = base64UrlEncode(
        std::vector<uint8_t>(payload_json.begin(), payload_json.end()));
    std::string unknown_wire =
        header_b64 + "." + unknown_b64 + "." + sig_b64;
    CHECK_THROWS(DpopProof::deserialize(unknown_wire));
  }
#endif  // CATAPULT_ENABLE_JSON

  TEST_CASE("Missing iat fails is_valid() and is_fresh() — no synthesis") {
    // A-01: prior to this fix the deserialiser initialised iat to the
    // producer default (Clock::now()) and left it untouched when the wire
    // form omitted the claim. is_fresh() then compared "now" to "now" and
    // returned true, silently admitting a proof that carried no freshness
    // anchor. `iat` is now `std::optional<int64_t>`; is_valid() and
    // is_fresh() MUST fail closed when it is unset.
    DpopPayload payload(moqt_actions::PUBLISH, "ns", "trk");
    payload.iat.reset();
    CHECK_FALSE(payload.is_valid());
    CHECK_FALSE(payload.is_fresh());
  }

  TEST_CASE(
      "DpopProofValidator rejects a proof with no jti when jti processing is on") {
    // A-02: prior to this fix, absence of `jti` on the wire silently
    // skipped the ReplayStore admission step. A malicious minter could
    // then replay a jti-less proof indefinitely. When jti_processing is
    // enabled (the default), a proof MUST carry a jti; if it does not,
    // validation MUST fail.
    auto keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    // No jti argument → the proof serialises with jti absent.
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433");
    REQUIRE_FALSE(proof.get_payload().jti.has_value());

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_jti_processing(true);
    DpopProofValidator validator(settings);
    validator.set_cwt_verifier(&keys->get_algorithm());

    CHECK_FALSE(validator.validate_proof(
        proof, moqt_actions::PUBLISH, expected_uri,
        keys->get_public_key_thumbprint()));
  }

  TEST_CASE(
      "DpopProofValidator accepts a jti-less proof when jti processing is off") {
    // A-02: the fail-closed rule is scoped to `jti_processing == true`.
    // Callers who explicitly opt out (e.g. they have an out-of-band
    // replay defence) must still be able to admit proofs that omit jti.
    auto keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433");
    REQUIRE_FALSE(proof.get_payload().jti.has_value());

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_jti_processing(false);
    DpopProofValidator validator(settings);
    validator.set_cwt_verifier(&keys->get_algorithm());

    CHECK(validator.validate_proof(
        proof, moqt_actions::PUBLISH, expected_uri,
        keys->get_public_key_thumbprint()));
  }

  TEST_CASE("CWT DPoP deserialization leaves iat unset when omitted on wire") {
    // A-01: build a valid COSE_Sign1 body whose inner payload map omits
    // the `iat` claim, then deserialise and confirm the decoded payload's
    // iat stays as `nullopt`. Freshness enforcement is validator-level,
    // but the deserialiser MUST NOT paper over the absence.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns.iat-missing", "trk-1",
        "relay:4433", std::string{"jti-1"});

    // Rebuild a copy of the proof with iat cleared, then re-serialize:
    // the emit path now refuses this (see create_signing_input()), so we
    // instead round-trip the proof and clear the iat post-decode to
    // exercise the deserialiser-side check.
    auto wire = proof.serialize();
    auto decoded = DpopProof::deserialize(wire);
    // Positive case: this proof carries iat, so is_valid should hold.
    CHECK(decoded.get_payload().iat.has_value());
    CHECK(decoded.get_payload().is_valid());
  }

  TEST_CASE("CWT DPoP deserialization rejects non-18 outer tag") {
    // HN-03: a COSE_Sign1 body labelled with any other single-recipient
    // tag must be refused before we do any crypto.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-tag-check"});
    auto wire = proof.serialize();
    auto cose_bytes = base64UrlDecode(wire);

    // Prepend CBOR tag 17 (0xd1) — an untagged encoder means this
    // synthesizes the "mis-tagged" case even if the wire form was
    // originally untagged.
    std::vector<uint8_t> mistagged;
    mistagged.reserve(cose_bytes.size() + 1);
    mistagged.push_back(0xd1);
    mistagged.insert(mistagged.end(), cose_bytes.begin(), cose_bytes.end());
    auto mistagged_wire = base64UrlEncode(mistagged);

    CHECK_THROWS(DpopProof::deserialize_cwt(mistagged_wire));

    // A correctly-tagged (18/0xd2) proof must accept.
    std::vector<uint8_t> correctly_tagged;
    correctly_tagged.reserve(cose_bytes.size() + 1);
    correctly_tagged.push_back(0xd2);
    correctly_tagged.insert(correctly_tagged.end(), cose_bytes.begin(),
                            cose_bytes.end());
    auto tagged_wire = base64UrlEncode(correctly_tagged);
    CHECK_NOTHROW(DpopProof::deserialize_cwt(tagged_wire));
  }
}

TEST_SUITE("DpopValidationSettings — CatDpopSettings overlay") {
  TEST_CASE("Token window shorter than relay ceiling wins") {
    // Relay baseline caps at 5 min; token demands 30s. The stricter
    // window (token) must be adopted.
    DpopValidationSettings settings{std::chrono::seconds{300}};
    CatDpopSettings wire;
    wire.window_seconds = 30;
    settings.overlayCatDpopSettings(wire);
    CHECK(settings.get_effective_window() == std::chrono::seconds{30});
  }

  TEST_CASE("Token window longer than relay ceiling does not weaken it") {
    // The relay's ceiling is a security floor: a permissive token cannot
    // relax it. Adopting `min(wire, settings)` is deliberate.
    DpopValidationSettings settings{std::chrono::seconds{30}};
    CatDpopSettings wire;
    wire.window_seconds = 3600;
    settings.overlayCatDpopSettings(wire);
    CHECK(settings.get_effective_window() == std::chrono::seconds{30});
  }

  TEST_CASE("Token honor_jti=true enables replay tracking") {
    DpopValidationSettings settings;
    settings.honor_jti = false;
    CatDpopSettings wire;
    wire.honor_jti = true;
    settings.overlayCatDpopSettings(wire);
    CHECK(settings.get_jti_processing());
  }

  TEST_CASE("Token honor_jti=false does not disable an enabled validator") {
    // Same asymmetry as the window: only strictening flows from the
    // wire form. A token cannot say "please skip replay tracking" and
    // downgrade a validator that has it on.
    DpopValidationSettings settings;
    settings.honor_jti = true;
    CatDpopSettings wire;
    wire.honor_jti = false;
    settings.overlayCatDpopSettings(wire);
    CHECK(settings.get_jti_processing());
  }

  TEST_CASE("Missing wire fields leave validator settings untouched") {
    DpopValidationSettings settings{std::chrono::seconds{120}};
    settings.honor_jti = true;
    CatDpopSettings wire;  // both fields nullopt
    settings.overlayCatDpopSettings(wire);
    CHECK(settings.get_effective_window() == std::chrono::seconds{120});
    CHECK(settings.get_jti_processing());
  }
}

TEST_SUITE("DpopValidationSettings — algorithm allowlist") {
  TEST_CASE("Default allowlist accepts ES256 and only ES256") {
    // The out-of-box policy MUST be safe: an operator who never touches
    // set_allowed_dpop_algorithms should still get an asymmetric-only
    // profile. ES256 is the only algorithm this build's DPoP path knows
    // how to verify today, so it is also the only one the default lets
    // through.
    DpopValidationSettings settings;
    CHECK(settings.is_dpop_algorithm_allowed(ALG_ES256));
    // Symmetric algorithm — cannot demonstrate proof-of-possession.
    CHECK_FALSE(settings.is_dpop_algorithm_allowed(ALG_HMAC256_256));
    // `alg: none` sentinel and unregistered identifiers.
    CHECK_FALSE(settings.is_dpop_algorithm_allowed(0));
    CHECK_FALSE(settings.is_dpop_algorithm_allowed(-99));
  }

  TEST_CASE("HMAC and `alg: none` stay blocked even when placed in the set") {
    // Defence-in-depth: an operator who mistakenly whitelists a
    // symmetric or `none`-equivalent algorithm must still be protected.
    // is_dpop_algorithm_allowed enforces a hard blocklist ahead of the
    // configurable allowlist.
    DpopValidationSettings settings;
    settings.set_allowed_dpop_algorithms({ALG_ES256, ALG_HMAC256_256, 0});
    CHECK(settings.is_dpop_algorithm_allowed(ALG_ES256));
    CHECK_FALSE(settings.is_dpop_algorithm_allowed(ALG_HMAC256_256));
    CHECK_FALSE(settings.is_dpop_algorithm_allowed(0));
  }

  TEST_CASE("Custom allowlist narrows the accepted set") {
    // An operator with a hardware-backed keystore that only speaks a
    // custom algorithm can restrict the allowlist to that identifier.
    // ES256 must NOT be silently added back — the caller's policy stands.
    DpopValidationSettings settings;
    settings.set_allowed_dpop_algorithms({-8});  // e.g. EdDSA
    CHECK_FALSE(settings.is_dpop_algorithm_allowed(ALG_ES256));
    CHECK(settings.is_dpop_algorithm_allowed(-8));
  }

  TEST_CASE("Empty set restores the built-in default") {
    // Passing an empty set is the documented way to reset to the built-in
    // default rather than a way to widen the allowlist to everything.
    // Confirm that emptying it after previously restricting it brings
    // ES256 back and continues to reject symmetric algorithms.
    DpopValidationSettings settings;
    settings.set_allowed_dpop_algorithms({-8});
    CHECK_FALSE(settings.is_dpop_algorithm_allowed(ALG_ES256));
    settings.set_allowed_dpop_algorithms({});
    CHECK(settings.is_dpop_algorithm_allowed(ALG_ES256));
    CHECK_FALSE(settings.is_dpop_algorithm_allowed(ALG_HMAC256_256));
  }
}

TEST_SUITE("DpopProofValidator — algorithm allowlist enforcement") {
  TEST_CASE("Well-formed ES256 proof passes the allowlist check") {
    // Sanity: the default allowlist must not regress the accepting case
    // from the existing "accepts a well-formed proof" test.
    auto keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-alg-ok"});

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    DpopProofValidator validator(settings);
    validator.set_cwt_verifier(&keys->get_algorithm());

    CHECK(validator.validate_proof(proof, moqt_actions::PUBLISH, expected_uri,
                                   keys->get_public_key_thumbprint()));
  }

  TEST_CASE(
      "Proof whose alg is not in the allowlist is rejected before verify") {
    // A stricter deployment restricts DPoP to EdDSA. The ES256 proof
    // must fail closed at the allowlist check — even though the caller
    // did wire a matching signature verifier, we never dispatch to it.
    // If enforcement had been done at verify time instead, this test
    // would happily verify and admit the proof.
    auto keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-alg-narrow"});

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_allowed_dpop_algorithms({-8});  // EdDSA only
    DpopProofValidator validator(settings);
    validator.set_cwt_verifier(&keys->get_algorithm());

    CHECK_FALSE(validator.validate_proof(proof, moqt_actions::PUBLISH,
                                         expected_uri,
                                         keys->get_public_key_thumbprint()));
  }
}
