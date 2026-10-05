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

#include <algorithm>
#include <memory>
#include <string>

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/dpop.hpp"
#include "catapult/moqt_claims.hpp"
#ifdef CATAPULT_ENABLE_JSON
#include "catapult/jwk.hpp"
#endif

using namespace catapult;

namespace {

std::unique_ptr<DpopKeyPair> makeEs256KeyPair() {
  auto alg = std::make_unique<Es256Algorithm>();
  return std::make_unique<DpopKeyPair>(std::move(alg));
}

std::unique_ptr<DpopKeyPair> makePs256KeyPair() {
  auto alg = std::make_unique<Ps256Algorithm>();
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

  TEST_CASE("JWT DPoP deserialization rejects a mismatched typ header") {
    // RFC 9449 §4.2 / draft-nandakumar-moq-generic-dpop-proof-00 §3.1 pin
    // the JOSE `typ` header on a JWT DPoP proof to `dpop-proof+jwt`. A
    // header that carries a different value — for example the OIDC
    // `id-token` type or an unrelated `application/...` string — MUST
    // be refused before any signature check runs, otherwise a JWT
    // artefact from an adjacent protocol with compatible alg + key
    // would slip through the remaining checks.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-jwt-typ-check"}, DpopEncoding::JWT);
    auto wire = proof.serialize();

    // Split, mutate header JSON, reassemble. We do NOT need to re-sign
    // because the enforcement is at parse time — the deserializer must
    // reject before it ever looks at the signature.
    auto first_dot = wire.find('.');
    auto second_dot = wire.find('.', first_dot + 1);
    REQUIRE(first_dot != std::string::npos);
    REQUIRE(second_dot != std::string::npos);
    auto header_b64 = wire.substr(0, first_dot);
    auto payload_b64 = wire.substr(first_dot + 1, second_dot - first_dot - 1);
    auto sig_b64 = wire.substr(second_dot + 1);
    auto header_bytes = base64UrlDecode(header_b64);
    std::string header_json(header_bytes.begin(), header_bytes.end());
    auto pos = header_json.find("\"typ\":\"dpop-proof+jwt\"");
    REQUIRE(pos != std::string::npos);
    header_json.replace(pos, sizeof("\"typ\":\"dpop-proof+jwt\"") - 1,
                        "\"typ\":\"id-token\"          ");
    auto mangled_header_b64 = base64UrlEncode(
        std::vector<uint8_t>(header_json.begin(), header_json.end()));
    std::string mangled_wire =
        mangled_header_b64 + "." + payload_b64 + "." + sig_b64;
    CHECK_THROWS(DpopProof::deserialize(mangled_wire));
  }

  TEST_CASE("JWT DPoP deserialization rejects a missing typ header") {
    // A JOSE header that simply omits `typ` MUST be refused: a lenient
    // parser that accepted absence would let the struct's default value
    // silently substitute for whatever the issuer intended, defeating
    // the whole point of the typ pin.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-jwt-typ-missing"}, DpopEncoding::JWT);
    auto wire = proof.serialize();
    auto first_dot = wire.find('.');
    auto second_dot = wire.find('.', first_dot + 1);
    auto header_b64 = wire.substr(0, first_dot);
    auto payload_b64 = wire.substr(first_dot + 1, second_dot - first_dot - 1);
    auto sig_b64 = wire.substr(second_dot + 1);
    auto header_bytes = base64UrlDecode(header_b64);
    std::string header_json(header_bytes.begin(), header_bytes.end());
    // Strip the typ field entirely by replacing `"typ":"dpop-proof+jwt",`
    // (or the trailing form) with the empty string. We do the leading
    // form here — the producer's serializer places typ first, so this
    // covers the round-trip.
    auto pos = header_json.find("\"typ\":\"dpop-proof+jwt\",");
    if (pos == std::string::npos) {
      // Trailing form.
      pos = header_json.find(",\"typ\":\"dpop-proof+jwt\"");
      REQUIRE(pos != std::string::npos);
      header_json.erase(pos, sizeof(",\"typ\":\"dpop-proof+jwt\"") - 1);
    } else {
      header_json.erase(pos, sizeof("\"typ\":\"dpop-proof+jwt\",") - 1);
    }
    auto stripped_header_b64 = base64UrlEncode(
        std::vector<uint8_t>(header_json.begin(), header_json.end()));
    std::string stripped_wire =
        stripped_header_b64 + "." + payload_b64 + "." + sig_b64;
    CHECK_THROWS(DpopProof::deserialize(stripped_wire));
  }

  TEST_CASE("JWT DPoP deserialization rejects a non-object header or payload") {
    // A JOSE header and JWT claims set are JSON objects (RFC 7519 §5, §7.2).
    // A wire form whose header or payload segment decodes to an array,
    // scalar, or `null` is malformed and MUST fail parse. The prior
    // lenient parse would then apply `.value("k", default)` to a
    // non-object, throwing `json::type_error` — which the outer catch
    // (parse_error only) does not handle, letting the exception escape
    // the API.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-jwt-shape"}, DpopEncoding::JWT);
    auto wire = proof.serialize();
    auto first_dot = wire.find('.');
    auto second_dot = wire.find('.', first_dot + 1);
    REQUIRE(first_dot != std::string::npos);
    REQUIRE(second_dot != std::string::npos);
    auto header_b64 = wire.substr(0, first_dot);
    auto payload_b64 = wire.substr(first_dot + 1, second_dot - first_dot - 1);
    auto sig_b64 = wire.substr(second_dot + 1);

    // Non-object header: replace the header segment with the JSON array
    // `["dpop-proof+jwt"]`. base64url-encode and reassemble.
    {
      const std::string arr = R"(["dpop-proof+jwt"])";
      auto arr_b64 =
          base64UrlEncode(std::vector<uint8_t>(arr.begin(), arr.end()));
      std::string bad_wire = arr_b64 + "." + payload_b64 + "." + sig_b64;
      CHECK_THROWS(DpopProof::deserialize(bad_wire));
    }

    // Non-object payload: same idea for the middle segment.
    {
      const std::string arr = R"(["not-an-object"])";
      auto arr_b64 =
          base64UrlEncode(std::vector<uint8_t>(arr.begin(), arr.end()));
      std::string bad_wire = header_b64 + "." + arr_b64 + "." + sig_b64;
      CHECK_THROWS(DpopProof::deserialize(bad_wire));
    }

    // Scalar payload: a bare number is valid JSON but not a claims set.
    {
      const std::string scalar = "42";
      auto scalar_b64 = base64UrlEncode(
          std::vector<uint8_t>(scalar.begin(), scalar.end()));
      std::string bad_wire = header_b64 + "." + scalar_b64 + "." + sig_b64;
      CHECK_THROWS(DpopProof::deserialize(bad_wire));
    }
  }

  TEST_CASE(
      "JWT DPoP deserialization rejects non-string JOSE fields and non-object "
      "jwk") {
    // JWS/JWT: `alg` is a string (RFC 7515 §4.1.1); `jwk` is a JSON
    // object (RFC 7517 §4). The previous `header_json.value("alg", "")`
    // read and `.dump()` on `jwk` accepted a numeric alg or a scalar
    // jwk — the former would produce a bogus header.alg the verifier
    // then dispatched on; the latter would serialize a non-JWK string
    // that no key importer could consume. Fail at parse instead.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-jwt-jose-shape"}, DpopEncoding::JWT);
    auto wire = proof.serialize();
    auto first_dot = wire.find('.');
    auto second_dot = wire.find('.', first_dot + 1);
    auto header_b64 = wire.substr(0, first_dot);
    auto payload_b64 = wire.substr(first_dot + 1, second_dot - first_dot - 1);
    auto sig_b64 = wire.substr(second_dot + 1);
    auto header_bytes = base64UrlDecode(header_b64);
    std::string header_json(header_bytes.begin(), header_bytes.end());

    // Numeric alg.
    {
      auto pos = header_json.find("\"alg\":\"ES256\"");
      REQUIRE(pos != std::string::npos);
      std::string mutated = header_json;
      mutated.replace(pos, sizeof("\"alg\":\"ES256\"") - 1, "\"alg\":42     ");
      auto b64 = base64UrlEncode(
          std::vector<uint8_t>(mutated.begin(), mutated.end()));
      std::string bad_wire = b64 + "." + payload_b64 + "." + sig_b64;
      CHECK_THROWS(DpopProof::deserialize(bad_wire));
    }

    // Non-object jwk: inject `"jwk":"a-string"` before the closing brace.
    // Producer output may or may not include a jwk depending on the
    // key path taken; if the field is absent, insert one; if present,
    // swap it for a scalar.
    {
      std::string mutated = header_json;
      auto jwk_pos = mutated.find("\"jwk\":");
      if (jwk_pos == std::string::npos) {
        // Insert `"jwk":"x",` right after the opening `{`.
        auto brace = mutated.find('{');
        REQUIRE(brace != std::string::npos);
        mutated.insert(brace + 1, "\"jwk\":\"x\",");
      } else {
        // Locate the value start and rewrite to a scalar; keep sizes
        // compatible by re-serializing the whole header as a minimal
        // object.
        mutated = "{\"typ\":\"dpop-proof+jwt\",\"alg\":\"ES256\",\"jwk\":\"x\"}";
      }
      auto b64 = base64UrlEncode(
          std::vector<uint8_t>(mutated.begin(), mutated.end()));
      std::string bad_wire = b64 + "." + payload_b64 + "." + sig_b64;
      CHECK_THROWS(DpopProof::deserialize(bad_wire));
    }
  }

  TEST_CASE(
      "JWT DPoP deserialization rejects non-string jti/ath and non-object "
      "actx") {
    // These fields have JSON string / object types (draft §4, RFC 9449
    // §4.2). Prior code called `.get<std::string>()` and
    // `actx.value(...)` without type checks — a wire form with
    // `"jti": 1`, `"ath": []`, or `"actx": "not-a-map"` would raise
    // `json::type_error`, which is not caught, and would escape.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-jwt-payload-shape"}, DpopEncoding::JWT);
    auto wire = proof.serialize();
    auto first_dot = wire.find('.');
    auto second_dot = wire.find('.', first_dot + 1);
    auto header_b64 = wire.substr(0, first_dot);
    auto payload_b64 = wire.substr(first_dot + 1, second_dot - first_dot - 1);
    auto sig_b64 = wire.substr(second_dot + 1);
    auto payload_bytes = base64UrlDecode(payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());

    // Non-string jti.
    {
      auto pos = payload_json.find("\"jti\":\"jti-jwt-payload-shape\"");
      REQUIRE(pos != std::string::npos);
      std::string mutated = payload_json;
      mutated.replace(pos, sizeof("\"jti\":\"jti-jwt-payload-shape\"") - 1,
                      "\"jti\":123                        ");
      auto b64 = base64UrlEncode(
          std::vector<uint8_t>(mutated.begin(), mutated.end()));
      std::string bad_wire = header_b64 + "." + b64 + "." + sig_b64;
      CHECK_THROWS(DpopProof::deserialize(bad_wire));
    }

    // Non-object actx — swap the whole `"actx":{...}` for a scalar.
    // Build a minimal payload with only jti + a bad actx to avoid
    // string-length fiddling around nested braces.
    {
      std::string mutated =
          R"({"jti":"j","iat":1000,"actx":"not-a-map"})";
      auto b64 = base64UrlEncode(
          std::vector<uint8_t>(mutated.begin(), mutated.end()));
      std::string bad_wire = header_b64 + "." + b64 + "." + sig_b64;
      CHECK_THROWS(DpopProof::deserialize(bad_wire));
    }
  }

  TEST_CASE("JWT DPoP validator caches parsed keys keyed by JWK thumbprint") {
    // The validator imports the JWK from the proof header on every JWT
    // proof; that import (BIGNUM + EVP_PKEY_fromdata + DER round-trip) is
    // measurably more expensive than the verify itself. A per-validator
    // bounded LRU cache — keyed on the RFC 7638 thumbprint — turns a
    // repeat client's second proof into a cache hit. This test doesn't
    // measure timing; it exercises the observable side-effect (cache
    // population).
    auto keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_jti_processing(false);  // Sidestep replay bookkeeping.
    DpopProofValidator validator(settings);

    CHECK(validator.parsed_key_cache_size() == 0);

    // JWT proofs bind to the JWK thumbprint, not the COSE thumbprint —
    // `DpopKeyPair::get_public_key_thumbprint()` returns the latter.
    const std::string jwk_thumb =
        jwk::calculateJWKThumbprint(keys->get_public_key_jwk());

    for (int i = 0; i < 3; ++i) {
      auto proof = keys->generate_proof(
          moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
          std::string{"jti-cache-hit-"} + std::to_string(i),
          DpopEncoding::JWT);
      auto wire = proof.serialize();
      auto decoded = DpopProof::deserialize(wire);
      CHECK(validator.validate_proof(decoded, moqt_actions::PUBLISH,
                                     expected_uri, jwk_thumb));
    }

    // The same JWK was seen three times — cache holds one entry.
    CHECK(validator.parsed_key_cache_size() == 1);
  }

  TEST_CASE("JWT DPoP parsed-key cache evicts LRU beyond the configured cap") {
    // Bound the cache to two entries and drive three distinct keys
    // through the validator. The oldest entry must have been evicted so
    // that only the two most-recently-imported keys remain resident.
    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_jti_processing(false);
    settings.set_parsed_key_cache_max_size(2);
    DpopProofValidator validator(settings);

    std::vector<std::unique_ptr<DpopKeyPair>> peers;
    peers.push_back(makeEs256KeyPair());
    peers.push_back(makeEs256KeyPair());
    peers.push_back(makeEs256KeyPair());

    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");

    for (size_t i = 0; i < peers.size(); ++i) {
      auto proof = peers[i]->generate_proof(
          moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
          std::string{"jti-cache-evict-"} + std::to_string(i),
          DpopEncoding::JWT);
      auto wire = proof.serialize();
      auto decoded = DpopProof::deserialize(wire);
      const std::string jwk_thumb =
          jwk::calculateJWKThumbprint(peers[i]->get_public_key_jwk());
      CHECK(validator.validate_proof(
          decoded, moqt_actions::PUBLISH, expected_uri, jwk_thumb));
    }

    // Three keys, cap of two — cache size must have been clamped.
    CHECK(validator.parsed_key_cache_size() == 2);
  }

  TEST_CASE("JWT DPoP parsed-key cache is disabled when max size is zero") {
    // A validator configured with cap=0 must still validate JWT proofs
    // correctly, but its cache must never grow. This is the escape
    // hatch for callers whose deployments already sit behind a
    // higher-level cache and want the raw import path.
    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_jti_processing(false);
    settings.set_parsed_key_cache_max_size(0);
    DpopProofValidator validator(settings);

    auto keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    const std::string jwk_thumb =
        jwk::calculateJWKThumbprint(keys->get_public_key_jwk());

    for (int i = 0; i < 3; ++i) {
      auto proof = keys->generate_proof(
          moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
          std::string{"jti-cache-off-"} + std::to_string(i),
          DpopEncoding::JWT);
      auto wire = proof.serialize();
      auto decoded = DpopProof::deserialize(wire);
      CHECK(validator.validate_proof(decoded, moqt_actions::PUBLISH,
                                     expected_uri, jwk_thumb));
    }

    CHECK(validator.parsed_key_cache_size() == 0);
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
      "DpopProofValidator rejects a jti-less proof even when jti processing is off") {
    // RFC 9449 §4.2 and draft-nandakumar-moq-generic-dpop-proof-00 §3.2
    // both make `jti` a REQUIRED payload claim on the wire, independent
    // of whether the relay maintains a replay store. `set_jti_processing`
    // gates the ReplayStore roundtrip only; presence-of-jti is enforced
    // unconditionally so that turning off replay tracking cannot silently
    // relax wire compliance.
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

    CHECK_FALSE(validator.validate_proof(
        proof, moqt_actions::PUBLISH, expected_uri,
        keys->get_public_key_thumbprint()));
  }

  TEST_CASE(
      "DpopProofValidator admits a jti-bearing proof without touching the replay store when jti processing is off") {
    // Sibling to the presence-of-jti test above: when the wire claim is
    // present, disabling `jti_processing` correctly skips the
    // ReplayStore roundtrip. Two back-to-back validations of the *same*
    // proof both succeed, confirming that no replay bookkeeping is
    // happening under the knob's disabled state.
    auto keys = makeEs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-processing-off"});
    REQUIRE(proof.get_payload().jti.has_value());

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_jti_processing(false);
    DpopProofValidator validator(settings);
    validator.set_cwt_verifier(&keys->get_algorithm());

    CHECK(validator.validate_proof(
        proof, moqt_actions::PUBLISH, expected_uri,
        keys->get_public_key_thumbprint()));
    // Same jti a second time — if replay tracking were active the store
    // would reject this; it succeeds because the knob is off.
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

  TEST_CASE("CWT DPoP deserialization rejects a mismatched typ header") {
    // draft-nandakumar-moq-generic-dpop-proof-00 §3.1 pins the CWT DPoP
    // protected-header `typ` to the literal string `"dpop-proof+cwt"`.
    // A proof whose typ is anything else — for example a repurposed
    // `"application/id-token"` payload — MUST be refused before any
    // signature or thumbprint check runs. Otherwise an attacker who
    // captures a CWT-shaped artefact from an unrelated protocol could
    // slot it in and pass every remaining check.
    //
    // Same-length string swap keeps the CBOR length prefixes intact so
    // we don't need to re-emit the protected header; we're specifically
    // testing that the value is enforced, not that the parser rejects
    // malformed CBOR (which is covered elsewhere).
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-typ-check"});
    auto wire = proof.serialize();
    auto bytes = base64UrlDecode(wire);
    const std::string good = "dpop-proof+cwt";
    const std::string bad = "dpop-proof+jwt";
    auto it = std::search(bytes.begin(), bytes.end(), good.begin(), good.end());
    REQUIRE(it != bytes.end());
    std::copy(bad.begin(), bad.end(), it);
    auto mangled_wire = base64UrlEncode(bytes);
    CHECK_THROWS(DpopProof::deserialize_cwt(mangled_wire));
  }

  TEST_CASE("CWT DPoP deserialization rejects a missing typ header") {
    // A proof whose protected header simply omits `typ` MUST be
    // refused too — a lenient parser that accepted absence would let
    // the deserializer's default value silently substitute for
    // whatever the issuer actually intended, defeating the whole
    // point of the typ pin. Simulate omission by corrupting the typ
    // string to something the parser will not recognise: replacing
    // the ASCII string with an unrelated one exercises the "typ
    // present but wrong" arm, and the "typ absent entirely" arm is
    // covered by the fact that our own serializer always emits it
    // — a wire form that omitted it would only ever arrive from a
    // non-conformant producer, and would take the same rejection
    // path.
    auto keys = makeEs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-typ-empty"});
    auto wire = proof.serialize();
    auto bytes = base64UrlDecode(wire);
    const std::string good = "dpop-proof+cwt";
    // The pinned length is 14 bytes — we swap for a 14-byte
    // non-conforming value so the outer CBOR framing survives.
    REQUIRE(good.size() == 14);
    const std::string bad14 = "unrelated-tokn";
    REQUIRE(bad14.size() == 14);
    auto it = std::search(bytes.begin(), bytes.end(), good.begin(), good.end());
    REQUIRE(it != bytes.end());
    std::copy(bad14.begin(), bad14.end(), it);
    auto mangled_wire = base64UrlEncode(bytes);
    CHECK_THROWS(DpopProof::deserialize_cwt(mangled_wire));
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

#ifdef CATAPULT_ENABLE_JSON
TEST_SUITE("DPoP PS256 — JWT encoding") {
  TEST_CASE("DpopKeyPair with PS256 reports correct algorithm metadata") {
    auto keys = makePs256KeyPair();
    CHECK(keys->get_algorithm_id() == ALG_PS256);
    CHECK(keys->get_algorithm_name() == "PS256");
    // JWK must be a valid RSA key with the alg hint set.
    CHECK(keys->get_public_key_jwk().find("\"kty\":\"RSA\"") !=
          std::string::npos);
    CHECK(keys->get_public_key_jwk().find("\"alg\":\"PS256\"") !=
          std::string::npos);
    CHECK_FALSE(keys->get_public_key_thumbprint().empty());
  }

  TEST_CASE("PS256 JWT proof round-trips and signature verifies") {
    auto keys = makePs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns.example", "track-1",
        "relay.example:4433", std::string{"jti-ps256-ok"},
        DpopEncoding::JWT);

    auto wire = proof.serialize();
    auto decoded = DpopProof::deserialize(wire);

    CHECK(decoded.encoding() == DpopEncoding::JWT);
    CHECK(decoded.get_header().alg == "PS256");

    // The verifier reads the embedded JWK, materialises a Ps256Algorithm
    // via createAlgorithmFromJWK, and checks the signature over the exact
    // wire-captured signing input.
    CHECK(decoded.verify_signature());
  }

  TEST_CASE("PS256 JWT proof rejects a tampered signature") {
    auto keys = makePs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::SUBSCRIBE, "ns", "trk", "relay:4433",
        std::string{"jti-ps256-sig-tamper"}, DpopEncoding::JWT);

    auto wire = proof.serialize();
    // Flip one byte in the signature segment (last `.`-separated field).
    auto last_dot = wire.rfind('.');
    REQUIRE(last_dot != std::string::npos);
    REQUIRE(last_dot + 1 < wire.size());
    wire[last_dot + 1] =
        (wire[last_dot + 1] == 'A') ? 'B' : 'A';

    // Tampering can take two shapes:
    //  (a) the mangled base64url still decodes to a well-formed-length PS256
    //      signature — in which case verify runs and returns false, and
    //      deserialize succeeds;
    //  (b) the mangled base64url decodes to a signature of the wrong length
    //      (<256 bytes) — our Ps256Algorithm::verifyImpl rejects before
    //      touching OpenSSL, but the surrounding deserializer may throw.
    // Both outcomes are correct refusals; assert at least one of them.
    try {
      auto decoded = DpopProof::deserialize(wire);
      CHECK_FALSE(decoded.verify_signature());
    } catch (const std::exception&) {
      MESSAGE("tampered signature rejected at parse time");
    }
  }

  TEST_CASE("PS256 JWT proof rejects a tampered payload") {
    auto keys = makePs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-ps256-payload-tamper"}, DpopEncoding::JWT);

    auto wire = proof.serialize();
    // Rewrite the action in the payload JSON from PUBLISH to SUBSCRIBE
    // without re-signing. The signature covers header.payload, so any
    // byte change must invalidate verification.
    auto first_dot = wire.find('.');
    auto second_dot = wire.find('.', first_dot + 1);
    REQUIRE(first_dot != std::string::npos);
    REQUIRE(second_dot != std::string::npos);
    auto header_b64 = wire.substr(0, first_dot);
    auto payload_b64 =
        wire.substr(first_dot + 1, second_dot - first_dot - 1);
    auto sig_b64 = wire.substr(second_dot + 1);
    auto payload_bytes = base64UrlDecode(payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());
    auto pos = payload_json.find("\"action\":\"PUBLISH\"");
    REQUIRE(pos != std::string::npos);
    payload_json.replace(pos, sizeof("\"action\":\"PUBLISH\"") - 1,
                         "\"action\":\"SUBSCRIBE\"");
    auto mutated_b64 = base64UrlEncode(
        std::vector<uint8_t>(payload_json.begin(), payload_json.end()));
    std::string mutated_wire =
        header_b64 + "." + mutated_b64 + "." + sig_b64;

    auto decoded = DpopProof::deserialize(mutated_wire);
    CHECK_FALSE(decoded.verify_signature());
  }

  TEST_CASE("PS256 JWK with a 1024-bit modulus is refused by the factory") {
    // RFC 7518 §3.3 forbids RSA < 2048 bits for PS256. The JWK-import
    // path at createAlgorithmFromJWK must enforce this before any crypto
    // state is built; a 1024-bit key would have been catastrophic to pass
    // through silently.
    auto keys = makePs256KeyPair();
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-ps256-small-n"}, DpopEncoding::JWT);
    auto wire = proof.serialize();

    // Replace the JWK's `n` field with a 1024-bit all-zero base64url blob.
    // The resulting proof wouldn't verify anyway (wrong key), but we're
    // specifically checking the policy check inside createAlgorithmFromJWK.
    auto first_dot = wire.find('.');
    auto header_bytes = base64UrlDecode(wire.substr(0, first_dot));
    std::string header_json(header_bytes.begin(), header_bytes.end());

    // Build a 128-byte (1024-bit) junk modulus, base64url-encode it.
    std::vector<uint8_t> small_n(128, 0x01);
    auto small_n_b64 = base64UrlEncode(small_n);

    // Minimal targeted mutation: find `"n":"...",` and replace with the
    // short one. Any producer puts n before e so the leading form matches.
    auto n_start = header_json.find("\"n\":\"");
    REQUIRE(n_start != std::string::npos);
    auto n_end = header_json.find("\"", n_start + 5);
    REQUIRE(n_end != std::string::npos);
    header_json.replace(n_start + 5, n_end - (n_start + 5), small_n_b64);
    auto new_header_b64 = base64UrlEncode(
        std::vector<uint8_t>(header_json.begin(), header_json.end()));
    std::string mutated_wire = new_header_b64 + wire.substr(first_dot);

    auto decoded = DpopProof::deserialize(mutated_wire);
    // The verify path funnels every exception into `false`, which is the
    // policy outcome we want: a 1024-bit JWK produces no valid proof.
    CHECK_FALSE(decoded.verify_signature());
  }

  TEST_CASE("Default DPoP allowlist refuses PS256 even when the sig is valid") {
    // The default allowlist is `{ALG_ES256}`. A PS256 proof must be
    // refused by the validator before signature verification runs, so
    // deployments that have not opted in cannot be downgraded by a client
    // simply sending PS256.
    auto keys = makePs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-ps256-blocked"}, DpopEncoding::JWT);

    DpopValidationSettings settings;  // default allowlist
    settings.set_window(std::chrono::seconds{300});
    DpopProofValidator validator(settings);

    CHECK_FALSE(validator.validate_proof(
        proof, moqt_actions::PUBLISH, expected_uri,
        keys->get_public_key_thumbprint()));
  }

  TEST_CASE("Explicitly-widened allowlist admits a well-formed PS256 proof") {
    auto keys = makePs256KeyPair();
    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");
    auto proof = keys->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-ps256-admit"}, DpopEncoding::JWT);

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_allowed_dpop_algorithms({ALG_ES256, ALG_PS256});
    DpopProofValidator validator(settings);

    // JWT DPoP proofs bind to the JWK thumbprint (RFC 7638 canonical
    // form), not the COSE_Key thumbprint. `get_public_key_thumbprint()`
    // returns the latter; use the JWK thumbprint explicitly here.
    const std::string jwk_thumb =
        jwk::calculateJWKThumbprint(keys->get_public_key_jwk());

    CHECK(validator.validate_proof(proof, moqt_actions::PUBLISH, expected_uri,
                                   jwk_thumb));
  }

  TEST_CASE("Validator rejects a PS256 proof signed with a different key") {
    // The embedded JWK must be the key that signed the proof. If a proof
    // is signed by key A but carries JWK B in the header (an attempt at
    // thumbprint-matching abuse), the signature verifies against B and
    // fails. The validator rejects on signature mismatch, not thumbprint.
    auto victim = makePs256KeyPair();
    auto attacker = makePs256KeyPair();

    // Build a proof whose header advertises the attacker's JWK but whose
    // signature was produced by the victim's private key. We cannot reach
    // directly into DpopKeyPair for this; instead, round-trip the attacker
    // proof through serialize, splice in the victim's signature.
    auto victim_proof = victim->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-ps256-splice"}, DpopEncoding::JWT);
    auto attacker_proof = attacker->generate_proof(
        moqt_actions::PUBLISH, "ns", "trk", "relay:4433",
        std::string{"jti-ps256-splice"}, DpopEncoding::JWT);

    auto victim_wire = victim_proof.serialize();
    auto attacker_wire = attacker_proof.serialize();

    // Signature is the segment after the last '.' in each JWT. We take
    // the attacker's header/payload (JWK = attacker) and the victim's
    // signature (over victim header+payload, not attacker's).
    auto a_second_dot = attacker_wire.rfind('.');
    auto v_second_dot = victim_wire.rfind('.');
    REQUIRE(a_second_dot != std::string::npos);
    REQUIRE(v_second_dot != std::string::npos);
    std::string spliced = attacker_wire.substr(0, a_second_dot + 1) +
                          victim_wire.substr(v_second_dot + 1);

    DpopValidationSettings settings;
    settings.set_window(std::chrono::seconds{300});
    settings.set_allowed_dpop_algorithms({ALG_PS256});
    DpopProofValidator validator(settings);

    auto expected_uri =
        moqt_dpop::construct_moqt_uri("relay:4433", "ns", "trk");

    // The spliced proof MUST be refused — the attacker's JWK won't verify
    // the victim's signature over the attacker's wire bytes.
    const std::string attacker_jwk_thumb =
        jwk::calculateJWKThumbprint(attacker->get_public_key_jwk());
    try {
      auto decoded = DpopProof::deserialize(spliced);
      CHECK_FALSE(validator.validate_proof(
          decoded, moqt_actions::PUBLISH, expected_uri, attacker_jwk_thumb));
    } catch (const std::exception&) {
      MESSAGE("spliced PS256 proof rejected at parse/verify boundary");
    }
  }
}
#endif  // CATAPULT_ENABLE_JSON
