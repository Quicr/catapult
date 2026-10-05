#include <doctest/doctest.h>
#include "catapult/crypto.hpp"

using namespace catapult;

TEST_CASE("Base64UrlEncoding") {
    std::vector<uint8_t> data = {0x4d, 0x61, 0x6e}; // "Man"
    std::string encoded = base64UrlEncode(data);
    CHECK(encoded == "TWFu");
    
    auto decoded = base64UrlDecode(encoded);
    CHECK(decoded == data);
}

TEST_CASE("Base64UrlEncodingPadding") {
    std::vector<uint8_t> data = {0x4d, 0x61}; // "Ma"
    std::string encoded = base64UrlEncode(data);
    CHECK(encoded == "TWE"); // No padding in URL-safe base64
    
    auto decoded = base64UrlDecode(encoded);
    CHECK(decoded == data);
}

TEST_CASE("Base64UrlInvalidCharacter") {
    REQUIRE_THROWS_AS(base64UrlDecode("TW@u"), InvalidBase64Error);
}

TEST_CASE("Sha256Hash") {
    std::vector<uint8_t> testData = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
    auto hash = hashSha256(testData);
    CHECK(hash.size() == 32); // SHA256 produces 32-byte hash
    
    // Test that same input produces same hash
    auto hash2 = hashSha256(testData);
    CHECK(hash == hash2);
    
    // Test that different input produces different hash
    std::vector<uint8_t> differentData = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    auto differentHash = hashSha256(differentData);
    CHECK(hash != differentHash);
}

TEST_CASE("CreateJwtSigningInput") {
    std::vector<uint8_t> header = {0x7b, 0x22, 0x61, 0x6c, 0x67, 0x22, 0x3a, 0x22, 0x48, 0x53, 0x32, 0x35, 0x36, 0x22, 0x7d}; // {"alg":"HS256"}
    std::vector<uint8_t> payload = {0x7b, 0x22, 0x73, 0x75, 0x62, 0x22, 0x3a, 0x22, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x22, 0x7d}; // {"sub":"1234567890"}
    
    auto signingInput = createJwtSigningInput(header, payload);
    
    // Should be base64url(header) + "." + base64url(payload)
    std::string expected = base64UrlEncode(header) + "." + base64UrlEncode(payload);
    std::string actual(signingInput.begin(), signingInput.end());
    
    CHECK(actual == expected);
}

TEST_CASE("HmacSha256GenerateKey") {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    CHECK(key.size() == 32); // 256 bits = 32 bytes
    
    // Generate another key and verify they're different
    auto key2 = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    CHECK(key != key2);
}

TEST_CASE("HmacSha256SignAndVerify") {
    std::vector<uint8_t> testData = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm algorithm(key);
    
    auto signature = algorithm.sign(testData);
    CHECK_FALSE(signature.empty());
    
    // Verify with correct key
    CHECK(algorithm.verify(testData, signature));
    
    // Verify with different data should fail
    std::vector<uint8_t> differentData = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    CHECK_FALSE(algorithm.verify(differentData, signature));
    
    // Verify with different key should fail
    auto key2 = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm algorithm2(key2);
    CHECK_FALSE(algorithm2.verify(testData, signature));
}

TEST_CASE("HmacSha256AlgorithmId") {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm algorithm(key);
    
    CHECK(algorithm.algorithmId() == ALG_HMAC256_256);
}

TEST_CASE("Es256GenerateKeyPair") {
    auto keyPair = Es256Algorithm::generateSecureKeyPair();
    CHECK_FALSE(keyPair.first.empty());  // Private key
    CHECK_FALSE(keyPair.second.empty()); // Public key

    auto keyPair2 = Es256Algorithm::generateSecureKeyPair();
    CHECK(secure_utils::to_regular_vector(keyPair.first) !=
          secure_utils::to_regular_vector(keyPair2.first));
    CHECK(keyPair.second != keyPair2.second);
}

TEST_CASE("Es256AlgorithmId") {
    Es256Algorithm algorithm;
    CHECK(algorithm.algorithmId() == ALG_ES256);
}

// Note: Full Es256 sign/verify tests would require proper key loading
// which is not fully implemented in the simplified version

TEST_SUITE("Ps256Algorithm") {

    TEST_CASE("algorithm id reports COSE PS256 (-37)") {
        Ps256Algorithm algorithm;
        CHECK(algorithm.algorithmId() == ALG_PS256);
        CHECK(ALG_PS256 == -37);
    }

    TEST_CASE("generateSecureKeyPair yields distinct nonempty keys") {
        auto a = Ps256Algorithm::generateSecureKeyPair();
        auto b = Ps256Algorithm::generateSecureKeyPair();
        CHECK_FALSE(a.first.empty());
        CHECK_FALSE(a.second.empty());
        CHECK(secure_utils::to_regular_vector(a.first) !=
              secure_utils::to_regular_vector(b.first));
        CHECK(a.second != b.second);
    }

    TEST_CASE("generateSecureKeyPair rejects out-of-range modulus sizes") {
        CHECK_THROWS_AS(Ps256Algorithm::generateSecureKeyPair(1024),
                        CryptoError);
        CHECK_THROWS_AS(
            Ps256Algorithm::generateSecureKeyPair(
                static_cast<int>(crypto_constants::PS256_MAX_MODULUS_BITS) + 1),
            CryptoError);
    }

    TEST_CASE("sign/verify round-trip succeeds with same key pair") {
        auto kp = Ps256Algorithm::generateSecureKeyPair();
        Ps256Algorithm signer(kp.first, kp.second);
        Ps256Algorithm verifier(kp.second);  // verify-only

        std::vector<uint8_t> msg = {'h', 'e', 'l', 'l', 'o', ' ',
                                    'P', 'S', '2', '5', '6'};
        auto sig = signer.sign(msg);
        CHECK_FALSE(sig.empty());

        // PS256 signature size equals the modulus size in bytes (2048/8 = 256).
        CHECK(sig.size() == 256);

        CHECK(signer.verify(msg, sig));
        CHECK(verifier.verify(msg, sig));
    }

    TEST_CASE("verify fails on tampered payload") {
        auto kp = Ps256Algorithm::generateSecureKeyPair();
        Ps256Algorithm alg(kp.first, kp.second);

        std::vector<uint8_t> msg = {'o', 'r', 'i', 'g'};
        auto sig = alg.sign(msg);

        auto tampered = msg;
        tampered[0] ^= 0x01;
        CHECK_FALSE(alg.verify(tampered, sig));
    }

    TEST_CASE("verify fails on tampered signature") {
        auto kp = Ps256Algorithm::generateSecureKeyPair();
        Ps256Algorithm alg(kp.first, kp.second);

        std::vector<uint8_t> msg = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
        auto sig = alg.sign(msg);

        auto tampered = sig;
        tampered.back() ^= 0xFF;
        CHECK_FALSE(alg.verify(msg, tampered));
    }

    TEST_CASE("verify fails under wrong public key") {
        auto kp1 = Ps256Algorithm::generateSecureKeyPair();
        auto kp2 = Ps256Algorithm::generateSecureKeyPair();
        Ps256Algorithm signer(kp1.first, kp1.second);
        Ps256Algorithm wrong(kp2.second);  // verify-only, wrong pub

        std::vector<uint8_t> msg = {'x', 'y', 'z'};
        auto sig = signer.sign(msg);

        CHECK_FALSE(wrong.verify(msg, sig));
        // Sanity: the real verifier still passes.
        Ps256Algorithm right(kp1.second);
        CHECK(right.verify(msg, sig));
    }

    TEST_CASE("verify fails on wrong signature length") {
        auto kp = Ps256Algorithm::generateSecureKeyPair();
        Ps256Algorithm alg(kp.second);

        std::vector<uint8_t> msg = {'a'};
        std::vector<uint8_t> short_sig(100, 0xAB);
        std::vector<uint8_t> long_sig(257, 0xAB);
        CHECK_FALSE(alg.verify(msg, short_sig));
        CHECK_FALSE(alg.verify(msg, long_sig));
    }

    TEST_CASE("sign without private key throws") {
        auto kp = Ps256Algorithm::generateSecureKeyPair();
        Ps256Algorithm verify_only(kp.second);

        std::vector<uint8_t> msg = {'q'};
        CHECK_THROWS_AS(verify_only.sign(msg), CryptoError);
    }

    TEST_CASE("loading a non-RSA key is rejected") {
        auto ec_kp = Es256Algorithm::generateSecureKeyPair();
        // ec_kp.second is a DER EC public key — PS256 must refuse it.
        CHECK_THROWS_AS(Ps256Algorithm(ec_kp.second), CryptoError);
    }

    TEST_CASE("getPublicKey round-trips through verify-only constructor") {
        auto kp = Ps256Algorithm::generateSecureKeyPair();
        Ps256Algorithm signer(kp.first, kp.second);
        auto pub = signer.getPublicKey();
        REQUIRE(pub == kp.second);

        Ps256Algorithm verifier(pub);
        std::vector<uint8_t> msg = {'r', 't'};
        auto sig = signer.sign(msg);
        CHECK(verifier.verify(msg, sig));
    }

    TEST_CASE("PS256 signature is salted (two signatures of same data differ)") {
        // RSASSA-PSS is probabilistic (unlike RSASSA-PKCS1-v1_5). Two sign
        // operations over the same message with the same key MUST produce
        // different signatures, both of which verify. If this ever fails,
        // the padding configuration has silently regressed to a
        // deterministic scheme.
        auto kp = Ps256Algorithm::generateSecureKeyPair();
        Ps256Algorithm alg(kp.first, kp.second);
        std::vector<uint8_t> msg = {'s', 'a', 'l', 't', 'e', 'd'};
        auto s1 = alg.sign(msg);
        auto s2 = alg.sign(msg);
        CHECK(s1 != s2);
        CHECK(alg.verify(msg, s1));
        CHECK(alg.verify(msg, s2));
    }
}