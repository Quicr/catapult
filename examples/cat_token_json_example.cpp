/**
 * @file cat_token_json_example.cpp
 * @brief Example demonstrating JSON serialization of CAT tokens with composite claims
 * 
 * This example shows how to:
 * 1. Create CAT tokens with various claim types
 * 2. Create composite claims (AND, OR, NOR)
 * 3. Pretty print tokens as JSON
 */

#include "catapult/token.hpp"
#include "catapult/token_factory.hpp"
#include "catapult/claims.hpp"
#include "catapult/moqt_claims.hpp"
#include "catapult/composite.hpp"
#include "catapult/json_serialization.hpp"

#include <iostream>
#include <chrono>
#include <memory>

using namespace catapult;

/**
 * @brief Create a sample CAT token with various claims
 */
CatToken create_sample_token() {
    CatToken token;
    
    // Core claims
    token.core.iss = "example-authority.com";
    token.core.aud = std::vector<std::string>{"client1.example.com", "client2.example.com"};
    token.core.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{2}
    );
    token.core.cti = "token-id-12345";
    
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
    token.cat.catgeoalt = 50; // meters
    
    // Network claims
    token.cat.catnip = std::vector<std::string>{"192.168.1.0/24", "10.0.0.0/8"};
    token.cat.catm = "GET,POST,PUT";
    token.cat.catalpn = std::vector<std::string>{"h3", "h2", "http/1.1"};
    token.cat.cath = std::vector<std::string>{"api.example.com", "*.example.com"};
    token.cat.catgeoiso3166 = std::vector<std::string>{"US", "CA"};
    
    // Informational claims
    token.informational.sub = "user123";
    token.informational.iat = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()
    );
    token.informational.catifdata = "interface-data-xyz";
    
    // DPoP claims
    token.dpop.cnf = "jwk-thumbprint-abc123";
    token.dpop.catdpop = "dpop-token-xyz";
    
    // Request claims  
    token.request.catif = "interface-data-123";
    token.request.catr = "request-data-456";
    
    // Custom claims
    token.custom[9999] = "custom-value-1";
    token.custom[9998] = "custom-value-2";
    
    return token;
}

/**
 * @brief Create a token with MOQT claims
 */
CatToken create_moqt_token() {
    CatToken token;
    
    // Basic claims
    token.core.iss = "moqt-authority.example.com";
    token.core.aud = std::vector<std::string>{"moqt-relay.example.com"};
    token.core.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{1}
    );
    
    // MOQT claims
    MoqtClaims moqt_claims = MoqtClaims::create(2);
    
    // Publisher permissions
    std::vector<int> publish_actions = {moqt_actions::PUBLISH};
    moqt_claims.addScope(
        publish_actions,
        MoqtBinaryMatch::exact("live-streams"),
        MoqtBinaryMatch::prefix("user123-")
    );
    
    // Subscriber permissions  
    std::vector<int> subscribe_actions = {moqt_actions::SUBSCRIBE, moqt_actions::FETCH};
    moqt_claims.addScope(
        subscribe_actions,
        MoqtBinaryMatch::exact("public-streams"),
        MoqtBinaryMatch::prefix("news-")
    );
    
    // Set revalidation interval
    moqt_claims.setRevalidationInterval(std::chrono::seconds{300});
    
    token.extended.setMoqtClaims(std::move(moqt_claims));
    
    return token;
}

/**
 * @brief Create a token with composite claims
 */
CatToken create_composite_token() {
    CatToken token;
    
    // Basic core claims
    token.core.iss = "composite-authority.example.com";
    token.core.aud = std::vector<std::string>{"composite-relay.example.com"};
    token.core.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{1}
    );
    
    // Create tokens for composite claims
    auto publisher_token = create_moqt_token();
    publisher_token.informational.sub = "publisher-user";
    publisher_token.core.iss = "publisher-authority.example.com";
    
    auto moderator_token = create_sample_token();
    moderator_token.informational.sub = "moderator-user";
    moderator_token.core.iss = "moderator-authority.example.com";
    // Remove some claims to make it smaller for display
    moderator_token.cat.catgeocoord.reset();
    moderator_token.cat.catgeoiso3166.reset();
    moderator_token.cat.catalpn.reset();
    moderator_token.dpop = DpopClaims{};
    
    auto admin_token = CatToken{};
    admin_token.core.iss = "admin-authority.example.com";
    admin_token.core.aud = std::vector<std::string>{"admin-system.example.com"};
    admin_token.core.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{24}
    );
    admin_token.informational.sub = "admin-user";
    admin_token.cat.catv = "admin-1.0";
    admin_token.cat.catpor = true;
    
    // Create OR composite: (Publisher OR Moderator)
    std::vector<ClaimSet> or_claim_sets;
    or_claim_sets.emplace_back(std::make_unique<CatToken>(std::move(publisher_token)));
    or_claim_sets.emplace_back(std::make_unique<CatToken>(std::move(moderator_token)));
    
    auto or_composite = composite_utils::createOrComposite(or_claim_sets);
    
    // Create AND composite: ((Publisher OR Moderator) AND Admin)
    std::vector<ClaimSet> and_claim_sets;
    and_claim_sets.emplace_back(std::make_unique<OrClaim>(*or_composite));
    and_claim_sets.emplace_back(std::make_unique<CatToken>(std::move(admin_token)));
    
    auto and_composite = composite_utils::createAndComposite(and_claim_sets);
    
    // Set the composite claims in the token
    token.composite.andClaim = std::move(and_composite);
    
    return token;
}

/**
 * @brief Create a complex nested composite token
 */
CatToken create_nested_composite_token() {
    CatToken token;
    
    // Basic core claims
    token.core.iss = "nested-authority.example.com";
    token.core.aud = std::vector<std::string>{"nested-system.example.com"};
    token.core.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + std::chrono::hours{2}
    );
    
    // Create simple tokens
    auto user_token = CatToken{};
    user_token.core.iss = "user-authority.example.com";
    user_token.informational.sub = "regular-user";
    user_token.cat.catv = "user-1.0";
    
    auto service_token = CatToken{};
    service_token.core.iss = "service-authority.example.com";
    service_token.informational.sub = "service-account";
    service_token.cat.catv = "service-1.0";
    
    auto blocked_token = CatToken{};
    blocked_token.core.iss = "blocked-authority.example.com";
    blocked_token.informational.sub = "blocked-user";
    blocked_token.core.exp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() - std::chrono::hours{1} // Expired
    );
    
    // Create NOR composite for blocked users
    std::vector<ClaimSet> nor_claim_sets;
    nor_claim_sets.emplace_back(std::make_unique<CatToken>(std::move(blocked_token)));
    auto nor_composite = composite_utils::createNorComposite(nor_claim_sets);
    
    // Create OR composite for valid users
    std::vector<ClaimSet> or_claim_sets;
    or_claim_sets.emplace_back(std::make_unique<CatToken>(std::move(user_token)));
    or_claim_sets.emplace_back(std::make_unique<CatToken>(std::move(service_token)));
    auto or_composite = composite_utils::createOrComposite(or_claim_sets);
    
    // Create final AND: (User OR Service) AND NOT Blocked
    std::vector<ClaimSet> final_claim_sets;
    final_claim_sets.emplace_back(std::make_unique<OrClaim>(*or_composite));
    final_claim_sets.emplace_back(std::make_unique<NorClaim>(*nor_composite));
    auto final_composite = composite_utils::createAndComposite(final_claim_sets);
    
    token.composite.orClaim = std::move(or_composite);
    token.composite.norClaim = std::move(nor_composite);
    token.composite.andClaim = std::move(final_composite);
    
    return token;
}

/**
 * @brief Helper function to output token in the selected format
 */
void output_token(const CatToken& token, bool pretty_print, int indent, bool base64_output) {
    if (base64_output) {
        std::cout << json_serialization::to_base64_json(token, pretty_print, indent) << "\n";
    } else {
        if (pretty_print) {
            std::cout << json_serialization::to_pretty_json(token, indent) << "\n";
        } else {
            std::cout << json_serialization::to_compact_json(token) << "\n";
        }
    }
}

/**
 * @brief Interactive conversion helper functions
 */
void process_base64_to_json(const std::string& base64_input) {
    try {
        std::cout << "=== Base64 to JSON Conversion ===\n";
        std::cout << "Input Base64: " << base64_input.substr(0, 80) << (base64_input.length() > 80 ? "..." : "") << "\n\n";
        
        // Decode base64 to JSON
        auto json_output = json_serialization::base64_utils::base64_to_json(base64_input);
        std::cout << "Decoded JSON:\n" << json_output << "\n\n";
        
        // Parse and validate as CatToken
        auto token = json_serialization::from_base64_json(base64_input);
        std::cout << "Successfully parsed as valid CatToken\n";
        std::cout << "Token issuer: " << (token.core.iss.has_value() ? *token.core.iss : "(none)") << "\n";
        std::cout << "Token expiry: " << (token.core.exp.has_value() ? std::to_string(*token.core.exp) : "(none)") << "\n\n";
        
    } catch (const std::exception& e) {
        std::cout << "Error processing base64 input: " << e.what() << "\n\n";
    }
}

void process_json_to_base64(const std::string& json_input) {
    try {
        std::cout << "=== JSON to Base64 Conversion ===\n";
        std::cout << "Input JSON: " << json_input.substr(0, 200) << (json_input.length() > 200 ? "..." : "") << "\n\n";
        
        // Convert JSON to base64
        auto base64_output = json_serialization::base64_utils::json_to_base64(json_input);
        std::cout << "Encoded Base64: " << base64_output << "\n\n";
        
        // Validate by parsing as JSON and then as CatToken
        auto j = nlohmann::json::parse(json_input);
        CatToken token;
        json_serialization::from_json(j, token);
        std::cout << "Successfully parsed as valid CatToken\n";
        std::cout << "Token issuer: " << (token.core.iss.has_value() ? *token.core.iss : "(none)") << "\n";
        std::cout << "Token expiry: " << (token.core.exp.has_value() ? std::to_string(*token.core.exp) : "(none)") << "\n\n";
        
    } catch (const std::exception& e) {
        std::cout << "Error processing JSON input: " << e.what() << "\n\n";
    }
}

/**
 * @brief Display base64 and JSON for sample tokens by claim type
 */
void show_claim_type_examples() {
    std::cout << "=== Token Examples by Claim Type ===\n\n";
    
    // Basic Core Claims Token
    std::cout << "1. CORE CLAIMS TOKEN:\n";
    std::cout << "============================\n\n";

    CatToken core_token;
    core_token.core.iss = "core-authority.example.com";
    core_token.core.aud = std::vector<std::string>{"client.example.com"};
    core_token.core.exp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours{1});
    core_token.core.cti = "core-token-123";
    
    std::cout << "Base64: " << json_serialization::to_base64_json(core_token, false) << "\n";
    std::cout << "JSON: " << json_serialization::to_compact_json(core_token) << "\n\n";
    
    // CAT Claims Token
    std::cout << "2. CAT CLAIMS TOKEN:\n";
    std::cout << "============================\n\n";
    CatToken cat_token;
    cat_token.core.iss = "cat-authority.example.com";
    cat_token.core.exp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours{2});
    cat_token.cat.catv = "1.0";
    cat_token.cat.catu = 50;
    cat_token.cat.catreplay = "replay-nonce-456";
    cat_token.cat.catpor = true;
    
    std::cout << "Base64: " << json_serialization::to_base64_json(cat_token, false) << "\n";
    std::cout << "JSON: " << json_serialization::to_compact_json(cat_token) << "\n\n";
    
    // Geographic Claims Token
    std::cout << "3. GEOGRAPHIC CLAIMS TOKEN:\n";
    std::cout << "============================\n\n";

    CatToken geo_token;
    geo_token.core.iss = "geo-authority.example.com";
    geo_token.core.exp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours{1});
    auto coord = GeoCoordinate::createSafe(40.7128, -74.0060); // NYC
    if (coord.has_value()) {
        coord->accuracy = 50.0;
        geo_token.cat.catgeocoord = coord.value();
    }
    geo_token.cat.geohash = "dr5reg";
    geo_token.cat.catgeoalt = 10;
    geo_token.cat.catgeoiso3166 = std::vector<std::string>{"US"};
    
    std::cout << "Base64: " << json_serialization::to_base64_json(geo_token, false) << "\n";
    std::cout << "JSON: " << json_serialization::to_compact_json(geo_token) << "\n\n";
    
    // Network Claims Token
    std::cout << "============================\n\n";
    std::cout << "4. NETWORK CLAIMS TOKEN:\n";
    std::cout << "============================\n\n";

    CatToken net_token;
    net_token.core.iss = "network-authority.example.com";
    net_token.core.exp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours{1});
    net_token.cat.catnip = std::vector<std::string>{"192.168.1.0/24"};
    net_token.cat.catm = "GET,POST";
    net_token.cat.catalpn = std::vector<std::string>{"h2", "http/1.1"};
    net_token.cat.cath = std::vector<std::string>{"api.example.com"};
    
    std::cout << "Base64: " << json_serialization::to_base64_json(net_token, false) << "\n";
    std::cout << "JSON: " << json_serialization::to_compact_json(net_token) << "\n\n";
    
    // DPoP Claims Token
    std::cout << "============================\n\n";
    std::cout << "5. DPOP CLAIMS TOKEN:\n";
    std::cout << "============================\n\n";

    CatToken dpop_token;
    dpop_token.core.iss = "dpop-authority.example.com";
    dpop_token.core.exp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours{1});
    dpop_token.dpop.cnf = "jwk-thumbprint-dpop-123";
    dpop_token.dpop.catdpop = "dpop-proof-token-xyz";
    
    std::cout << "Base64: " << json_serialization::to_base64_json(dpop_token, false) << "\n";
    std::cout << "JSON: " << json_serialization::to_compact_json(dpop_token) << "\n\n";
    
    // Request Claims Token
    std::cout << "============================\n\n";
    std::cout << "6. REQUEST CLAIMS TOKEN:\n";
    std::cout << "============================\n\n";

    CatToken req_token;
    req_token.core.iss = "request-authority.example.com";
    req_token.core.exp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours{1});
    req_token.request.catif = "interface-request-789";
    req_token.request.catr = "request-data-abc";
    
    std::cout << "Base64: " << json_serialization::to_base64_json(req_token, false) << "\n";
    std::cout << "JSON: " << json_serialization::to_compact_json(req_token) << "\n\n";
    
    // MOQT Claims Token
    std::cout << "============================\n\n";
    std::cout << "7. MOQT CLAIMS TOKEN:\n";
    std::cout << "============================\n\n";
    auto moqt_token = create_moqt_token();
    std::cout << "Base64: " << json_serialization::to_base64_json(moqt_token, false) << "\n";
    std::cout << "JSON: " << json_serialization::to_compact_json(moqt_token) << "\n\n";
}

/**
 * @brief Print usage information
 */
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  --pretty, -p     Pretty print JSON (default)\n";
    std::cout << "  --compact, -c    Compact JSON output\n";
    std::cout << "  --indent N       Pretty print with N spaces indent (default: 2)\n";
    std::cout << "  --base64, -b     Output as base64-encoded JSON\n";
    std::cout << "  --examples, -e   Show claim type examples\n";
    std::cout << "  --help, -h       Show this help message\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << "                # Pretty print with 2 spaces\n";
    std::cout << "  " << program_name << " --compact      # Compact JSON output\n";
    std::cout << "  " << program_name << " --indent 4     # Pretty print with 4 spaces\n";
    std::cout << "  " << program_name << " --base64       # Base64-encoded JSON output\n";
    std::cout << "  " << program_name << " --examples     # Show examples by claim type\n";
}

int main(int argc, char* argv[]) {
    bool pretty_print = true;
    int indent = 2;
    bool base64_output = false;
    bool show_examples = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        else if (arg == "--pretty" || arg == "-p") {
            pretty_print = true;
        }
        else if (arg == "--compact" || arg == "-c") {
            pretty_print = false;
        }
        else if (arg == "--base64" || arg == "-b") {
            base64_output = true;
        }
        else if (arg == "--examples" || arg == "-e") {
            show_examples = true;
        }
        else if (arg == "--indent" && i + 1 < argc) {
            try {
                indent = std::stoi(argv[i + 1]);
                i++; // Skip next argument
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid indent value: " << argv[i + 1] << std::endl;
                return 1;
            }
        }
        else {
            std::cerr << "Error: Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }
    
    std::cout << "CAT Token JSON Serialization Example\n";
    std::cout << "====================================\n\n";
    
    try {

        if (show_examples) {
            show_claim_type_examples();
            return 0;
        }

        
        // Example 1: Basic CAT token
        std::cout << "=== Example 1: Basic CAT Token ===\n";
        auto basic_token = create_sample_token();
        output_token(basic_token, pretty_print, indent, base64_output);
        std::cout << "\n";
        
        // Example 2: MOQT token
        std::cout << "=== Example 2: MOQT Token ===\n";
        auto moqt_token = create_moqt_token();
        output_token(moqt_token, pretty_print, indent, base64_output);
        std::cout << "\n";
        
        // Example 3: Composite claims token
        std::cout << "=== Example 3: Composite Claims Token ===\n";
        auto composite_token = create_composite_token();
        output_token(composite_token, pretty_print, indent, base64_output);
        std::cout << "\n";
        
        // Example 4: Nested composite claims
        std::cout << "=== Example 4: Nested Composite Claims ===\n";
        auto nested_token = create_nested_composite_token();
        output_token(nested_token, pretty_print, indent, base64_output);
        std::cout << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}