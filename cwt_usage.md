# CWT API Usage Guide

This document provides examples for using the CWT (CBOR Web Token) API with CAT tokens for different cryptographic operations: MAC, Encrypt, Single Signature, and Multi Signature.

## Table of Contents

- [MAC Operations](#mac-operations)
- [Encryption Operations](#encryption-operations)
- [Single Signature Operations](#single-signature-operations)
- [Multi Signature Operations](#multi-signature-operations)
- [Key Management](#key-management)
- [Error Handling](#error-handling)

## MAC Operations

Message Authentication Code (MAC) operations use HMAC-SHA256 to ensure message integrity and authenticity.

### Basic MAC Example

```cpp
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include "catapult/token.hpp"

using namespace catapult;

// Create a CAT token
CatToken token;
token.core.iss = "example-issuer";
token.core.aud = std::vector<std::string>{"audience1"};
token.core.exp = std::chrono::system_clock::to_time_t(
    std::chrono::system_clock::now() + std::chrono::hours{2}
);
token.cat.catv = "1.0";
token.cat.catu = 100;

// Generate secure HMAC key
auto hmacKey = HmacSha256Algorithm::generateSecureKey();
HmacSha256Algorithm hmacAlgo(hmacKey);

// Create and sign CWT with MAC
Cwt cwt(ALG_HMAC256_256, token);
cwt.withKeyId("mac-key-001");

std::string macCwt = cwt.createCwt(CwtMode::MACed, hmacAlgo);
std::cout << "MAC CWT: " << macCwt << std::endl;

// Verify MAC
try {
    auto verifiedCwt = Cwt::validateCwt(macCwt, hmacAlgo);
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
std::string macCwt1 = cwt.createCwt(CwtMode::MACed, hmacAlgo1);
std::string macCwt2 = cwt.createCwt(CwtMode::MACed, hmacAlgo2);

// Verify with appropriate keys
auto verified1 = Cwt::validateCwt(macCwt1, hmacAlgo1);
auto verified2 = Cwt::validateCwt(macCwt2, hmacAlgo2);
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

// Create and encrypt CWT
Cwt cwt(ALG_A256GCM, token);
cwt.withKeyId("aes-key-001");

std::string encryptedCwt = cwt.createCwt(CwtMode::Encrypted, aesAlgo);
std::cout << "Encrypted CWT: " << encryptedCwt << std::endl;

// Decrypt
try {
    auto decryptedCwt = Cwt::validateCwt(encryptedCwt, aesAlgo);
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

// Create and encrypt CWT
Cwt cwt(ALG_ChaCha20_Poly1305, token);
std::string encryptedCwt = cwt.createCwt(CwtMode::Encrypted, chachaAlgo);

// Decrypt
auto decryptedCwt = Cwt::validateCwt(encryptedCwt, chachaAlgo);
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

// Create and sign CWT
Cwt cwt(ALG_ES256, token);
cwt.withKeyId("es256-key-001");

std::string signedCwt = cwt.createCwt(CwtMode::Signed, signAlgo);
std::cout << "Signed CWT: " << signedCwt << std::endl;

// For verification (public key only)
Es256Algorithm verifyAlgo(publicKey);

try {
    auto verifiedCwt = Cwt::validateCwt(signedCwt, verifyAlgo);
    std::cout << "Signature verification successful!" << std::endl;
    std::cout << "Issuer: " << verifiedCwt.payload.core.iss.value_or("none") << std::endl;
} catch (const CryptoError& e) {
    std::cerr << "Signature verification failed: " << e.what() << std::endl;
}
```

### PS256 (RSA-PSS) Single Signature

```cpp
// Generate PS256 key pair
auto [rsaPrivateKey, rsaPublicKey] = Ps256Algorithm::generateSecureKeyPair();

// For signing
Ps256Algorithm signAlgo(rsaPrivateKey, rsaPublicKey);

// Create and sign CWT
Cwt cwt(ALG_PS256, token);
cwt.withKeyId("ps256-key-001");

std::string signedCwt = cwt.createCwt(CwtMode::Signed, signAlgo);

// For verification
Ps256Algorithm verifyAlgo(rsaPublicKey);
auto verifiedCwt = Cwt::validateCwt(signedCwt, verifyAlgo);
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
auto [ps256PrivKey, ps256PubKey] = Ps256Algorithm::generateSecureKeyPair();
auto hmacKey = HmacSha256Algorithm::generateSecureKey();

Es256Algorithm es256Algo(es256PrivKey, es256PubKey);
Ps256Algorithm ps256Algo(ps256PrivKey, ps256PubKey);
HmacSha256Algorithm hmacAlgo(hmacKey);

// Create CWT with primary algorithm
Cwt cwt(ALG_ES256, token);
cwt.withKeyId("multi-authority-key");

// Add multiple signatures
cwt.addSignature(es256Algo);  // PKI authority
cwt.addSignature(ps256Algo);  // Government authority  
cwt.addSignature(hmacAlgo);   // Internal authority

std::cout << "Added " << cwt.signatures.size() << " signatures" << std::endl;

// Create multi-signed CWT
std::string multiSignedCwt = cwt.createCwt(CwtMode::MultiSigned, es256Algo);
std::cout << "Multi-signed CWT: " << multiSignedCwt << std::endl;
```

### Multi Signature Verification

```cpp
// Create algorithm map for verification
std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithmMap;

// Use verification-only algorithms (public keys only)
Es256Algorithm es256VerifyAlgo(es256PubKey);
Ps256Algorithm ps256VerifyAlgo(ps256PubKey);

algorithmMap.emplace(ALG_ES256, std::cref(es256VerifyAlgo));
algorithmMap.emplace(ALG_PS256, std::cref(ps256VerifyAlgo));
algorithmMap.emplace(ALG_HMAC256_256, std::cref(hmacAlgo));

// Validate with per-signature algorithms
try {
    auto validatedCwt = Cwt::validateMultiSignedCwt(multiSignedCwt, algorithmMap);
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