/**
 * @file cat_cwt_crypto.cpp
 * @brief Example demonstrating CWT crypto operations with CAT tokens and composite claims
 * 
 * This example shows how to:
 * 1. Create CAT tokens with composite claims
 * 2. Perform COSE MAC, Sign, and Encrypt operations
 * 3. Support single vs multiple recipients
 * 4. Output results in hex format
 */

#include "catapult/token.hpp"
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include "catapult/claims.hpp"
#include "catapult/composite.hpp"
#include "catapult/base64.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <memory>
#include <vector>
#include <getopt.h>

using namespace catapult;

/**
 * @brief Convert bytes to hex string
 */
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto& byte : bytes) {
        oss << std::setw(2) << static_cast<unsigned>(byte);
    }
    return oss.str();
}

/**
 * @brief Convert hex string to bytes
 */
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

/**
 * @brief Create a CAT token with composite claims
 */
CatToken create_composite_cat_token() {
    CatToken token;
    
    // Core claims
    token.core.iss = "test-server.example.com";
    token.core.aud = std::vector<std::string>{"test-client.example.com"};
    token.core.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{2}
    );
    token.core.cti = "token-12345";
    
    // CAT claims
    token.cat.catv = "1.0";
    token.cat.catu = 100;
    token.cat.catreplay = "nonce-98765";
    token.cat.catpor = true;
    
    // Geographic claims
    auto coord = GeoCoordinate::createSafe(37.7749, -122.4194); // San Francisco
    if (coord.has_value()) {
        coord->accuracy = 100.0;
        token.cat.catgeocoord = coord.value();
    }
    token.cat.geohash = "9q8yy";
    token.cat.catgeoalt = 50;
    
    // Network claims
    token.cat.catnip = std::vector<std::string>{"192.168.1.0/24"};
    token.cat.catm = "GET,POST";
    token.cat.catalpn = std::vector<std::string>{"h3", "h2"};
    token.cat.cath = std::vector<std::string>{"api.example.com"};
    token.cat.catgeoiso3166 = std::vector<std::string>{"US"};
    
    // Create simple tokens for composite claims
    auto user_token = CatToken{};
    user_token.core.iss = "user-authority.example.com";
    user_token.core.aud = std::vector<std::string>{"user-service.example.com"};
    user_token.core.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{1}
    );
    user_token.informational.sub = "user123";
    user_token.cat.catv = "user-1.0";
    
    auto service_token = CatToken{};
    service_token.core.iss = "service-authority.example.com";
    service_token.core.aud = std::vector<std::string>{"service-endpoint.example.com"};
    service_token.core.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{1}
    );
    service_token.informational.sub = "service-account";
    service_token.cat.catv = "service-1.0";
    
    // Create OR composite: (User OR Service)
    std::vector<ClaimSet> or_claim_sets;
    or_claim_sets.emplace_back(std::make_unique<CatToken>(std::move(user_token)));
    or_claim_sets.emplace_back(std::make_unique<CatToken>(std::move(service_token)));
    
    auto or_composite = composite_utils::createOrComposite(or_claim_sets);
    token.composite.orClaim = std::move(or_composite);
    
    return token;
}

/**
 * @brief Perform HMAC operation
 */
void perform_hmac_operation(const CatToken& token, bool single_key) {
    std::cout << "\n=== HMAC-SHA256 Operation ===\n";
    
    try {
        // Generate key(s)
        auto key1 = HmacSha256Algorithm::generateSecureKey();
        std::cout << "HMAC Key 1: " << bytes_to_hex(std::vector<uint8_t>(key1.begin(), key1.end())) << "\n";
        
        HmacSha256Algorithm hmac_algo(key1);
        
        // Create CWT
        Cwt cwt(ALG_HMAC256_256, token);
        
        if (single_key) {
            // Single MAC
            std::string mac_cwt = cwt.createCwt(CwtMode::MACed, hmac_algo);
            std::cout << "Single MAC CWT (Base64): " << mac_cwt << "\n";
            std::cout << "Single MAC CWT (Hex): " << bytes_to_hex(base64UrlDecode(mac_cwt)) << "\n";
            
            // Verify
            auto verified_cwt = Cwt::validateCwt(mac_cwt, hmac_algo);
            std::cout << "MAC Verification: SUCCESS\n";
            std::cout << "Verified Token Issuer: " << (verified_cwt.payload.core.iss.has_value() ? *verified_cwt.payload.core.iss : "none") << "\n";
        } else {
            // Multiple MAC (for demonstration, we'll create multiple CWTs with different keys)
            auto key2 = HmacSha256Algorithm::generateSecureKey();
            std::cout << "HMAC Key 2: " << bytes_to_hex(std::vector<uint8_t>(key2.begin(), key2.end())) << "\n";
            
            HmacSha256Algorithm hmac_algo2(key2);
            
            std::string mac_cwt1 = cwt.createCwt(CwtMode::MACed, hmac_algo);
            std::string mac_cwt2 = cwt.createCwt(CwtMode::MACed, hmac_algo2);
            
            std::cout << "Multiple MAC CWT 1 (Base64): " << mac_cwt1 << "\n";
            std::cout << "Multiple MAC CWT 1 (Hex): " << bytes_to_hex(base64UrlDecode(mac_cwt1)) << "\n";
            std::cout << "Multiple MAC CWT 2 (Base64): " << mac_cwt2 << "\n";
            std::cout << "Multiple MAC CWT 2 (Hex): " << bytes_to_hex(base64UrlDecode(mac_cwt2)) << "\n";
            
            // Verify both
            auto verified_cwt1 = Cwt::validateCwt(mac_cwt1, hmac_algo);
            auto verified_cwt2 = Cwt::validateCwt(mac_cwt2, hmac_algo2);
            std::cout << "Multiple MAC Verification: SUCCESS\n";
        }
        
    } catch (const std::exception& e) {
        std::cout << "HMAC Operation Failed: " << e.what() << "\n";
    }
}

/**
 * @brief Perform signature operation
 */
void perform_sign_operation(const CatToken& token, bool single_signer) {
    std::cout << "\n=== ECDSA ES256 Signature Operation ===\n";
    
    try {
        // Generate key pair(s)
        auto [private_key1, public_key1] = Es256Algorithm::generateSecureKeyPair();
        std::cout << "ES256 Private Key 1: " << bytes_to_hex(std::vector<uint8_t>(private_key1.begin(), private_key1.end())) << "\n";
        std::cout << "ES256 Public Key 1: " << bytes_to_hex(public_key1) << "\n";
        
        Es256Algorithm sign_algo(private_key1, public_key1);
        
        // Create CWT
        Cwt cwt(ALG_ES256, token);
        
        if (single_signer) {
            // Single signature
            std::string signed_cwt = cwt.createCwt(CwtMode::Signed, sign_algo);
            std::cout << "Single Signature CWT (Base64): " << signed_cwt << "\n";
            std::cout << "Single Signature CWT (Hex): " << bytes_to_hex(base64UrlDecode(signed_cwt)) << "\n";
            
            // Verify with public key only
            Es256Algorithm verify_algo(public_key1);
            auto verified_cwt = Cwt::validateCwt(signed_cwt, verify_algo);
            std::cout << "Signature Verification: SUCCESS\n";
            std::cout << "Verified Token Issuer: " << (verified_cwt.payload.core.iss.has_value() ? *verified_cwt.payload.core.iss : "none") << "\n";
        } else {
            // Multiple signatures (for demonstration, we'll create multiple CWTs with different keys)
            auto [private_key2, public_key2] = Es256Algorithm::generateSecureKeyPair();
            std::cout << "ES256 Private Key 2: " << bytes_to_hex(std::vector<uint8_t>(private_key2.begin(), private_key2.end())) << "\n";
            std::cout << "ES256 Public Key 2: " << bytes_to_hex(public_key2) << "\n";
            
            Es256Algorithm sign_algo2(private_key2, public_key2);
            
            std::string signed_cwt1 = cwt.createCwt(CwtMode::Signed, sign_algo);
            std::string signed_cwt2 = cwt.createCwt(CwtMode::Signed, sign_algo2);
            
            std::cout << "Multiple Signature CWT 1 (Base64): " << signed_cwt1 << "\n";
            std::cout << "Multiple Signature CWT 1 (Hex): " << bytes_to_hex(base64UrlDecode(signed_cwt1)) << "\n";
            std::cout << "Multiple Signature CWT 2 (Base64): " << signed_cwt2 << "\n";
            std::cout << "Multiple Signature CWT 2 (Hex): " << bytes_to_hex(base64UrlDecode(signed_cwt2)) << "\n";
            
            // Verify both
            Es256Algorithm verify_algo1(public_key1);
            Es256Algorithm verify_algo2(public_key2);
            auto verified_cwt1 = Cwt::validateCwt(signed_cwt1, verify_algo1);
            auto verified_cwt2 = Cwt::validateCwt(signed_cwt2, verify_algo2);
            std::cout << "Multiple Signature Verification: SUCCESS\n";
        }
        
    } catch (const std::exception& e) {
        std::cout << "Signature Operation Failed: " << e.what() << "\n";
    }
}

/**
 * @brief Perform encryption operation
 */
void perform_encrypt_operation(const CatToken& token, bool single_recipient) {
    std::cout << "\n=== AES-GCM Encryption Operation ===\n";
    
    try {
        // Generate key(s) and IV(s)
        auto key1 = AesGcmAlgorithm::generateSecureKey(32); // AES-256
        auto iv1 = AesGcmAlgorithm::generateIV();
        std::cout << "AES Key 1: " << bytes_to_hex(std::vector<uint8_t>(key1.begin(), key1.end())) << "\n";
        std::cout << "AES IV 1: " << bytes_to_hex(iv1) << "\n";
        
        AesGcmAlgorithm aes_algo(key1, ALG_A256GCM);
        
        // Create CWT
        Cwt cwt(ALG_A256GCM, token);
        
        if (single_recipient) {
            // Single recipient
            std::string encrypted_cwt = cwt.createCwt(CwtMode::Encrypted, aes_algo);
            std::cout << "Single Recipient Encrypted CWT (Base64): " << encrypted_cwt << "\n";
            std::cout << "Single Recipient Encrypted CWT (Hex): " << bytes_to_hex(base64UrlDecode(encrypted_cwt)) << "\n";
            
            // Decrypt
            auto decrypted_cwt = Cwt::validateCwt(encrypted_cwt, aes_algo);
            std::cout << "Decryption: SUCCESS\n";
            std::cout << "Decrypted Token Issuer: " << (decrypted_cwt.payload.core.iss.has_value() ? *decrypted_cwt.payload.core.iss : "none") << "\n";
        } else {
            // Multiple recipients (for demonstration, we'll create multiple CWTs with different keys)
            auto key2 = AesGcmAlgorithm::generateSecureKey(32);
            auto iv2 = AesGcmAlgorithm::generateIV();
            std::cout << "AES Key 2: " << bytes_to_hex(std::vector<uint8_t>(key2.begin(), key2.end())) << "\n";
            std::cout << "AES IV 2: " << bytes_to_hex(iv2) << "\n";
            
            AesGcmAlgorithm aes_algo2(key2, ALG_A256GCM);
            
            std::string encrypted_cwt1 = cwt.createCwt(CwtMode::Encrypted, aes_algo);
            std::string encrypted_cwt2 = cwt.createCwt(CwtMode::Encrypted, aes_algo2);
            
            std::cout << "Multiple Recipients Encrypted CWT 1 (Base64): " << encrypted_cwt1 << "\n";
            std::cout << "Multiple Recipients Encrypted CWT 1 (Hex): " << bytes_to_hex(base64UrlDecode(encrypted_cwt1)) << "\n";
            std::cout << "Multiple Recipients Encrypted CWT 2 (Base64): " << encrypted_cwt2 << "\n";
            std::cout << "Multiple Recipients Encrypted CWT 2 (Hex): " << bytes_to_hex(base64UrlDecode(encrypted_cwt2)) << "\n";
            
            // Decrypt both
            auto decrypted_cwt1 = Cwt::validateCwt(encrypted_cwt1, aes_algo);
            auto decrypted_cwt2 = Cwt::validateCwt(encrypted_cwt2, aes_algo2);
            std::cout << "Multiple Recipients Decryption: SUCCESS\n";
        }
        
    } catch (const std::exception& e) {
        std::cout << "Encryption Operation Failed: " << e.what() << "\n";
    }
}

/**
 * @brief Print usage information
 */
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  --mac, -m        Perform MAC operations\n";
    std::cout << "  --sign, -s       Perform signature operations\n";
    std::cout << "  --encrypt, -e    Perform encryption operations\n";
    std::cout << "  --single         Use single recipient/key (default)\n";
    std::cout << "  --multiple       Use multiple recipients/keys\n";
    std::cout << "  --all, -a        Perform all operations\n";
    std::cout << "  --help, -h       Show this help message\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " --mac --single        # Single MAC operation\n";
    std::cout << "  " << program_name << " --sign --multiple     # Multiple signature operation\n";
    std::cout << "  " << program_name << " --encrypt             # Single encryption operation\n";
    std::cout << "  " << program_name << " --all --single        # All operations with single recipients\n";
}

int main(int argc, char* argv[]) {
    bool perform_mac = false;
    bool perform_sign = false;
    bool perform_encrypt = false;
    bool perform_all = false;
    bool single_mode = true; // Default to single mode
    
    // Command line options
    static struct option long_options[] = {
        {"mac", no_argument, 0, 'm'},
        {"sign", no_argument, 0, 's'},
        {"encrypt", no_argument, 0, 'e'},
        {"single", no_argument, 0, '1'},
        {"multiple", no_argument, 0, '2'},
        {"all", no_argument, 0, 'a'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "mse12ah", long_options, &option_index)) != -1) {
        switch (c) {
            case 'm':
                perform_mac = true;
                break;
            case 's':
                perform_sign = true;
                break;
            case 'e':
                perform_encrypt = true;
                break;
            case '1':
                single_mode = true;
                break;
            case '2':
                single_mode = false;
                break;
            case 'a':
                perform_all = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case '?':
                print_usage(argv[0]);
                return 1;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // If no specific operation requested and not --all, show help
    if (!perform_mac && !perform_sign && !perform_encrypt && !perform_all) {
        std::cout << "No operation specified. Use --help for options or --all to perform all operations.\n\n";
        perform_all = true;
    }
    
    std::cout << "CAT CWT Crypto Operations Example\n";
    std::cout << "=================================\n";
    std::cout << "Mode: " << (single_mode ? "Single" : "Multiple") << " recipient/key\n";
    
    try {
        // Create CAT token with composite claims
        std::cout << "\n=== Creating CAT Token with Composite Claims ===\n";
        auto token = create_composite_cat_token();
        
        std::cout << "Token:\n";
        std::cout << "Issuer: " << (token.core.iss.has_value() ? *token.core.iss : "none") << "\n";
        std::cout << "Audience: ";
        if (token.core.aud.has_value() && !token.core.aud->empty()) {
            std::cout << token.core.aud->front() << "\n";
        } else {
            std::cout << "none\n";
        }
        std::cout << "CAT Version: " << (token.cat.catv.has_value() ? *token.cat.catv : "none") << "\n";
        std::cout << "Has Composite Claims: " << (token.composite.orClaim ? "YES (OR)" : "NO") << "\n";
        
        // Perform operations based on command line arguments
        if (perform_all || perform_mac) {
            perform_hmac_operation(token, single_mode);
        }
        
        if (perform_all || perform_sign) {
            perform_sign_operation(token, single_mode);
        }
        
        if (perform_all || perform_encrypt) {
            perform_encrypt_operation(token, single_mode);
        }
        
        std::cout << "\n=== All Operations Completed Successfully ===\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}