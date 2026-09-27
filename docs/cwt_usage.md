# CWT API Usage Guide

This document provides examples for using the CWT (CBOR Web Token) API with CAT tokens for different cryptographic operations: MAC, Encrypt, Single Signature, and Multi Signature.

## Table of Contents

- [Token Creation](#token-creation)
- [MAC Operations](#mac-operations)
- [Encryption Operations](#encryption-operations)
- [Single Signature Operations](#single-signature-operations)
- [Multi Signature Operations](#multi-signature-operations)

## Token Creation

Use the `CatToken::builder()` fluent API to construct tokens:

```cpp
#include "catapult/token.hpp"

using namespace catapult;

using namespace std::chrono_literals;

// Basic token with core claims
auto token = CatToken::builder()
    .issuer("auth.example.com")
    .audience("api.example.com")
    .expiresIn(2h)
    .build();

// Token with DPoP binding (jkt is the SHA-256 thumbprint of the JWK)
auto dpopToken = CatToken::builder()
    .issuer("auth.moqt-cdn.example.com")
    .audience("relay.moqt-cdn.example.com")
    .expiresIn(1h)
    .dpopThumbprint(client_keys.get_public_key_thumbprint())
    .build();

// Token with geographic and network restrictions
CatNipEntry v4_nip{kRfc9164IPv4Tag, {192, 168, 1, 0}};
CatHostHeaderMatchList hosts{{
    CatHeaderMatch{"host",
                   {UriMatchType::Exact,
                    {'a','p','i','.','e','x','a','m','p','l','e','.','c','o','m'}}}}};
auto restrictedToken = CatToken::builder()
    .issuer("geo-auth.example.com")
    .audience("cdn.example.com")
    .expiresIn(1h)
    .geoCoordinate(37.7749, -122.4194, 100.0)  // lat, lon, radius (m)
    .countries({"US", "CA"})
    .networkInterfaces({v4_nip})
    .headerMatches(hosts)
    .alpn({{'h','3'}, {'h','2'}})  // ALPN protocol ids as byte strings
    .build();

// Token with CAT-specific claims
CatProofOfPossession por{
    /*probability=*/1.0,
    /*identifier=*/{0x01, 0x02, 0x03, 0x04},
    /*expiry=*/std::nullopt};
auto catToken = CatToken::builder()
    .issuer("cat-issuer.example.com")
    .audience("service.example.com")
    .expiresIn(1h)
    .version(1)                             // catv is a uint32
    .replayMode(CatReplayMode::RejectOnReplay)
    .proofOfPossession(std::move(por))
    .subject("user@example.com")
    .build();
```

## MAC Operations

Message Authentication Code (MAC) operations use HMAC-SHA256 to ensure message integrity and authenticity.

### Basic MAC Example

```cpp
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include "catapult/token.hpp"

using namespace catapult;

// Create a CAT token using builder pattern
using namespace std::chrono_literals;
auto token = CatToken::builder()
    .issuer("example-issuer")
    .audience("audience1")
    .expiresIn(2h)
    .version(1)
    .build();

// Generate secure HMAC key
auto hmacKey = HmacSha256Algorithm::generateSecureKey();
HmacSha256Algorithm hmacAlgo(hmacKey);

// Create and sign CWT with MAC using builder pattern
std::string macCwt = Cwt(ALG_HMAC256_256, token)
    .withKeyId("mac-key-001")
    .createCwtBase64(CwtMode::MACed, hmacAlgo);
std::cout << "MAC CWT: " << macCwt << std::endl;

// Verify MAC
try {
    auto verifiedCwt = Cwt::validateCwtBase64(macCwt, hmacAlgo);
    std::cout << "MAC verification successful!" << std::endl;
    std::cout << "Issuer: " << verifiedCwt.payload.core.iss.value_or("none") << std::endl;
} catch (const CryptoError& e) {
    std::cerr << "MAC verification failed: " << e.what() << std::endl;
}
```

### Multiple MAC Keys Example

```cpp
// For scenarios requiring multiple MAC keys (different authorities)
auto key1 = HmacSha256Algorithm::generateSecureKey();
auto key2 = HmacSha256Algorithm::generateSecureKey();

HmacSha256Algorithm hmacAlgo1(key1);
HmacSha256Algorithm hmacAlgo2(key2);

// Create separate CWTs with different keys
std::string macCwt1 = cwt.createCwtBase64(CwtMode::MACed, hmacAlgo1);
std::string macCwt2 = cwt.createCwtBase64(CwtMode::MACed, hmacAlgo2);

// Verify with appropriate keys
auto verified1 = Cwt::validateCwtBase64(macCwt1, hmacAlgo1);
auto verified2 = Cwt::validateCwtBase64(macCwt2, hmacAlgo2);
```

## Encryption Operations

Encryption operations use AEAD (Authenticated Encryption with Associated Data) algorithms like AES-GCM.

### AES-GCM Encryption Example

```cpp
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"

using namespace catapult;

// Create CAT token (same as above)
CatToken token;
// ... populate token fields ...

// Generate AES-256-GCM key and IV
auto aesKey = AesGcmAlgorithm::generateSecureKey(32); // 256-bit key
auto iv = AesGcmAlgorithm::generateIV();

AesGcmAlgorithm aesAlgo(aesKey, ALG_A256GCM);

// Create and encrypt CWT using builder pattern
std::string encryptedCwt = Cwt(ALG_A256GCM, token)
    .withKeyId("aes-key-001")
    .createCwtBase64(CwtMode::Encrypted, aesAlgo);
std::cout << "Encrypted CWT: " << encryptedCwt << std::endl;

// Decrypt
try {
    auto decryptedCwt = Cwt::validateCwtBase64(encryptedCwt, aesAlgo);
    std::cout << "Decryption successful!" << std::endl;
    std::cout << "Issuer: " << decryptedCwt.payload.core.iss.value_or("none") << std::endl;
} catch (const CryptoError& e) {
    std::cerr << "Decryption failed: " << e.what() << std::endl;
}
```


### ChaCha20-Poly1305 Encryption

```cpp
// Generate ChaCha20 key and nonce
auto chachaKey = ChaCha20Poly1305Algorithm::generateSecureKey();
auto nonce = ChaCha20Poly1305Algorithm::generateNonce();

ChaCha20Poly1305Algorithm chachaAlgo(chachaKey);

// Create and encrypt CWT using builder pattern
std::string encryptedCwt = Cwt(ALG_ChaCha20_Poly1305, token)
    .createCwtBase64(CwtMode::Encrypted, chachaAlgo);

// Decrypt
auto decryptedCwt = Cwt::validateCwtBase64(encryptedCwt, chachaAlgo);
```

## Single Signature Operations

Single signature operations use COSE_Sign1 format with algorithms like ECDSA ES256 or RSA PSS.

### ES256 (ECDSA) Single Signature

```cpp
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"

using namespace catapult;

// Create CAT token
CatToken token;
// ... populate token fields ...

// Generate ES256 key pair
auto [privateKey, publicKey] = Es256Algorithm::generateSecureKeyPair();

// For signing (requires private key)
Es256Algorithm signAlgo(privateKey, publicKey);

// Create and sign CWT using builder pattern
std::string signedCwt = Cwt(ALG_ES256, token)
    .withKeyId("es256-key-001")
    .createCwtBase64(CwtMode::Signed, signAlgo);
std::cout << "Signed CWT: " << signedCwt << std::endl;

// For verification (public key only)
Es256Algorithm verifyAlgo(publicKey);

try {
    auto verifiedCwt = Cwt::validateCwtBase64(signedCwt, verifyAlgo);
    std::cout << "Signature verification successful!" << std::endl;
    std::cout << "Issuer: " << verifiedCwt.payload.core.iss.value_or("none") << std::endl;
} catch (const CryptoError& e) {
    std::cerr << "Signature verification failed: " << e.what() << std::endl;
}
```

## Multi Signature Operations

Multi signature operations use COSE_Sign format to support multiple signatures with potentially different algorithms.

### Basic Multi Signature Example

```cpp
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include <map>

using namespace catapult;

// Create CAT token
CatToken token;
// ... populate token fields ...

// Create different algorithms
auto [es256PrivKey, es256PubKey] = Es256Algorithm::generateSecureKeyPair();
auto [es256bPrivKey, es256bPubKey] = Es256Algorithm::generateSecureKeyPair();
auto hmacKey = HmacSha256Algorithm::generateSecureKey();

Es256Algorithm es256Algo(es256PrivKey, es256PubKey);
Es256Algorithm es256bAlgo(es256bPrivKey, es256bPubKey);
HmacSha256Algorithm hmacAlgo(hmacKey);

// Create multi-signed CWT using builder pattern
std::string multiSignedCwt = Cwt(ALG_ES256, token)
    .withKeyId("multi-authority-key")
    .addSignature(es256Algo)    // PKI authority
    .addSignature(es256bAlgo)   // Secondary authority
    .addSignature(hmacAlgo)     // Internal authority
    .createCwtBase64(CwtMode::MultiSigned, es256Algo);
std::cout << "Multi-signed CWT: " << multiSignedCwt << std::endl;
```

### Multi Signature Verification

```cpp
// Create algorithm map for verification
std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithmMap;

// Use verification-only algorithms (public keys only). Note that a single
// algorithmMap entry per algorithm id is used; per-signature key lookup for
// same-alg-different-key deployments happens via a KeyResolver — see
// examples/cat_cwt_per_signature_example.cpp.
Es256Algorithm es256VerifyAlgo(es256PubKey);

algorithmMap.emplace(ALG_ES256, std::cref(es256VerifyAlgo));
algorithmMap.emplace(ALG_HMAC256_256, std::cref(hmacAlgo));

// Validate with per-signature algorithms
try {
    auto validatedCwt = Cwt::validateMultiSignedCwtBase64(multiSignedCwt, algorithmMap);
    std::cout << "Multi-signature validation successful!" << std::endl;
    std::cout << "Validated " << validatedCwt.signatures.size() << " signatures" << std::endl;
    
    // Display signature details
    for (size_t i = 0; i < validatedCwt.signatures.size(); ++i) {
        std::cout << "Signature " << i << " algorithm ID: " 
                  << validatedCwt.signatures[i].algorithmId << std::endl;
    }
} catch (const CryptoError& e) {
    std::cerr << "Multi-signature validation failed: " << e.what() << std::endl;
}
```





For more examples, see the `examples/` directory in the repository.