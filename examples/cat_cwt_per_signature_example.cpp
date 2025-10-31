/**
 * @file cat_cwt_per_signature_example.cpp
 * @brief Example demonstrating COSE_Sign with per-signature algorithm support
 * 
 * This example shows how to create CWTs with multiple signatures using different
 * algorithms and validate them with the per-signature validation method.
 */

#include <iostream>
#include <vector>
#include <memory>
#include <map>

#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include "catapult/logging.hpp"

using namespace catapult;

int main() {
    try {
        CAT_LOG_INFO("=== COSE_Sign with Per-Signature Algorithm Support ===");
        
        // Create a sample CAT token
        CatToken token;
        token.core.iss = "multi-alg-authority";
        token.core.aud = {"service-a", "service-b"};
        token.core.exp = 1234567890;
        token.cat.catv = "2.0";
        token.cat.catu = 100;
        
        CAT_LOG_INFO("Created CAT token with issuer: {}", token.core.iss.value_or("none"));
        
        // Create different cryptographic algorithms
        auto es256Algorithm = std::make_unique<Es256Algorithm>();
        auto ps256Algorithm = std::make_unique<Ps256Algorithm>();
        
        std::vector<uint8_t> hmacKey(reinterpret_cast<const uint8_t*>("hmac-secret-key-16"), 
                                     reinterpret_cast<const uint8_t*>("hmac-secret-key-16") + 16);
        auto hmacAlgorithm = std::make_unique<HmacSha256Algorithm>(hmacKey);

        // Create CWT with primary algorithm
        Cwt cwt(es256Algorithm->algorithmId(), token);
        cwt.withKeyId("multi-authority-key");

        // Add ES256 signature (PKI authority)
        cwt.addSignature(*es256Algorithm);

        // Add PS256 signature (Government authority)
        cwt.addSignature(*ps256Algorithm);

        // Add HMAC signature (Internal authority)
        cwt.addSignature(*hmacAlgorithm);

        // Display algorithm IDs for each signature
        for (size_t i = 0; i < cwt.signatures.size(); ++i) {
            CAT_LOG_INFO("  Signature {}: Algorithm ID {}", i, cwt.signatures[i].algorithmId);
        }
        
        // Create the multi-signed CWT using COSE_Sign format and use ES256 as primary
        std::string multiSignedCwt = cwt.createCwt(CwtMode::MultiSigned, *es256Algorithm);
        
        CAT_LOG_INFO("COSE_Sign CWT created successfully!");

        // Create algorithm map for validation
        std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>> algorithmMap;
        algorithmMap.emplace(es256Algorithm->algorithmId(), std::cref(*es256Algorithm));
        algorithmMap.emplace(ps256Algorithm->algorithmId(), std::cref(*ps256Algorithm));
        algorithmMap.emplace(hmacAlgorithm->algorithmId(), std::cref(*hmacAlgorithm));
        

        // Validate the multi-signed CWT with per-signature algorithms
        Cwt validatedCwt = Cwt::validateMultiSignedCwt(multiSignedCwt, algorithmMap);
        
        CAT_LOG_INFO("Validated signatures count: {}", validatedCwt.signatures.size());
        CAT_LOG_INFO("Decoded issuer: {}", validatedCwt.payload.core.iss.value_or("none"));
        CAT_LOG_INFO("Decoded audience count: {}", 
                     validatedCwt.payload.core.aud.has_value() ? 
                     validatedCwt.payload.core.aud->size() : 0);
        CAT_LOG_INFO("Decoded CAT version: {}", validatedCwt.payload.cat.catv.value_or("none"));
        CAT_LOG_INFO("Decoded CAT usage: {}", validatedCwt.payload.cat.catu.value_or(0));
        
        // Display validated signatures with their algorithm IDs
        CAT_LOG_INFO("Validated signatures:");
        for (size_t i = 0; i < validatedCwt.signatures.size(); ++i) {
            std::string algName = "Unknown";
            if (validatedCwt.signatures[i].algorithmId == es256Algorithm->algorithmId()) {
                algName = "ES256";
            } else if (validatedCwt.signatures[i].algorithmId == ps256Algorithm->algorithmId()) {
                algName = "PS256";
            } else if (validatedCwt.signatures[i].algorithmId == hmacAlgorithm->algorithmId()) {
                algName = "HMAC-SHA256";
            }
            CAT_LOG_INFO("  Signature {}: {} (ID: {})", i, algName, validatedCwt.signatures[i].algorithmId);
        }


        CAT_LOG_INFO("\n=== Example completed successfully! ===");

        return 0;
        
    } catch (const std::exception& e) {
        CAT_LOG_ERROR("Example failed: {}", e.what());
        return 1;
    }
}