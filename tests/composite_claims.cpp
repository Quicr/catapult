#include <doctest/doctest.h>
#include "catapult/claims.hpp"
#include "catapult/validator.hpp"
#include "catapult/error.hpp"
#include "catapult/composite.hpp"

using namespace catapult;
using namespace catapult::composite_utils;

CatToken createValidToken(const std::string& issuer = "test-issuer") {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    CoreClaims core;
    core.iss = issuer;
    core.aud = std::vector<std::string>{"test-audience"};
    core.exp = std::chrono::duration_cast<std::chrono::seconds>(exp.time_since_epoch()).count();
    core.cti = "test-id";
    
    auto tokenPtr = CatToken::createValidated(std::move(core));
    return *tokenPtr;
}

CatToken createExpiredToken() {
    auto past = std::chrono::system_clock::now() - std::chrono::hours(1);
    
    CoreClaims core;
    core.iss = "test-issuer";
    core.aud = std::vector<std::string>{"test-audience"};
    core.exp = std::chrono::duration_cast<std::chrono::seconds>(past.time_since_epoch()).count();
    core.cti = "expired-id";
    
    auto tokenPtr = CatToken::createValidated(std::move(core));
    return *tokenPtr;
}

TEST_CASE("CreateOrComposite") {
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    
    auto orComposite = createOrFromTokens({token1, token2});
    
    CHECK(orComposite->operation == CompositeOperator::OR);
    CHECK(orComposite->claims.size() == 2);
    CHECK(orComposite->getDepth() == 1);
}

TEST_CASE("CreateNorComposite") {
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    
    auto norComposite = createNorFromTokens({token1, token2});
    
    CHECK(norComposite->operation == CompositeOperator::NOR);
    CHECK(norComposite->claims.size() == 2);
    CHECK(norComposite->getDepth() == 1);
}

TEST_CASE("CreateAndComposite") {
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    
    auto andComposite = createAndFromTokens({token1, token2});
    
    CHECK(andComposite->operation == CompositeOperator::AND);
    CHECK(andComposite->claims.size() == 2);
    CHECK(andComposite->getDepth() == 1);
}

TEST_CASE("OrEvaluationWithValidTokens") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    
    auto orComposite = createOrFromTokens({token1, token2});
    
    // OR should succeed when at least one token is valid
    CHECK(orComposite->evaluate(validator));
}

TEST_CASE("OrEvaluationWithSomeInvalidTokens") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto validToken = createValidToken("valid-issuer");
    auto expiredToken = createExpiredToken();
    
    auto orComposite = createOrFromTokens({validToken, expiredToken});
    
    // OR should succeed when at least one token is valid
    CHECK(orComposite->evaluate(validator));
}

TEST_CASE("OrEvaluationWithAllInvalidTokens") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto expiredToken1 = createExpiredToken();
    auto expiredToken2 = createExpiredToken();
    
    auto orComposite = createOrFromTokens({expiredToken1, expiredToken2});
    
    // OR should fail when all tokens are invalid
    CHECK_FALSE(orComposite->evaluate(validator));
}

TEST_CASE("NorEvaluationWithAllInvalidTokens") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto expiredToken1 = createExpiredToken();
    auto expiredToken2 = createExpiredToken();
    
    auto norComposite = createNorFromTokens({expiredToken1, expiredToken2});
    
    // NOR should succeed when all tokens are invalid
    CHECK(norComposite->evaluate(validator));
}

TEST_CASE("NorEvaluationWithSomeValidTokens") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto validToken = createValidToken("valid-issuer");
    auto expiredToken = createExpiredToken();
    
    auto norComposite = createNorFromTokens({validToken, expiredToken});
    
    // NOR should fail when any token is valid
    CHECK_FALSE(norComposite->evaluate(validator));
}

TEST_CASE("AndEvaluationWithAllValidTokens") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    
    auto andComposite = createAndFromTokens({token1, token2});
    
    // AND should succeed when all tokens are valid
    CHECK(andComposite->evaluate(validator));
}

TEST_CASE("AndEvaluationWithSomeInvalidTokens") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto validToken = createValidToken("valid-issuer");
    auto expiredToken = createExpiredToken();
    
    auto andComposite = createAndFromTokens({validToken, expiredToken});
    
    // AND should fail when any token is invalid
    CHECK_FALSE(andComposite->evaluate(validator));
}

TEST_CASE("NestedCompositeDepth") {
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    auto token3 = createValidToken("issuer3");
    
    // Create nested structure: OR(token1, AND(token2, token3))
    auto innerAnd = createAndFromTokens({token2, token3});
    auto outerOr = std::make_unique<OrClaim>();
    outerOr->addToken(token1);
    ClaimSet nestedClaimSet(std::move(innerAnd));
    outerOr->addClaimSet(nestedClaimSet);
    
    CHECK(outerOr->getDepth() == 2);
}

TEST_CASE("NestedCompositeEvaluation") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto validToken1 = createValidToken("issuer1");
    auto validToken2 = createValidToken("issuer2");
    auto expiredToken = createExpiredToken();
    
    // Create nested structure: OR(validToken1, AND(validToken2, expiredToken))
    auto innerAnd = createAndFromTokens({validToken2, expiredToken});
    auto outerOr = std::make_unique<OrClaim>();
    outerOr->addToken(validToken1);
    ClaimSet nestedClaimSet2(std::move(innerAnd));
    outerOr->addClaimSet(nestedClaimSet2);
    
    // Should succeed because OR has one valid path (validToken1)
    CHECK(outerOr->evaluate(validator));
}

TEST_CASE("TokenWithCompositeClaimsValidation") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto validToken1 = createValidToken("issuer1");
    auto validToken2 = createValidToken("issuer2");
    
    auto orComposite = createOrFromTokens({validToken1, validToken2});
    
    auto tokenWithComposite = createValidToken("main-issuer")
        .withOrComposite(std::move(orComposite));
    
    // Main token validation should include composite claims validation
    REQUIRE_NOTHROW(validator.validate(tokenWithComposite));
}

TEST_CASE("TokenWithFailingCompositeClaimsValidation") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto expiredToken1 = createExpiredToken();
    auto expiredToken2 = createExpiredToken();
    
    auto andComposite = createAndFromTokens({expiredToken1, expiredToken2});
    
    auto tokenWithComposite = createValidToken("main-issuer")
        .withAndComposite(std::move(andComposite));
    
    // Should throw because composite claims validation fails
    REQUIRE_THROWS_AS(validator.validate(tokenWithComposite), InvalidClaimValueError);
}

TEST_CASE("DeepNestingDepthCheck") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    auto token = createValidToken("issuer");
    
    // Create deeply nested structure
    auto composite = std::make_unique<OrClaim>();
    composite->addToken(token);
    
    for (int i = 0; i < 15; ++i) {  // Create nesting deeper than MAX_NESTING_DEPTH
        auto newComposite = std::make_unique<OrClaim>();
        ClaimSet nestedClaimSet3(std::move(composite));
        newComposite->addClaimSet(nestedClaimSet3);
        composite = std::move(newComposite);
    }
    
    auto tokenWithDeepComposite = createValidToken("main-issuer")
        .withOrComposite(std::move(composite));
    
    // Should throw due to excessive nesting depth
    REQUIRE_THROWS_AS(validator.validate(tokenWithDeepComposite), InvalidClaimValueError);
}

TEST_CASE("CompositeClaimsContainerMethods") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    CompositeClaims container;
    
    CHECK_FALSE(container.hasComposites());
    
    auto orComposite = createOrFromTokens({createValidToken()});
    container.orClaim = std::move(orComposite);
    
    CHECK(container.hasComposites());
    
    // Test validation passes with valid composite
    CHECK(container.validateAll(validator));
}

TEST_CASE("ClaimSetCopyConstructor") {
    auto token = createValidToken("test-issuer");
    ClaimSet originalClaimSet(token);
    
    ClaimSet copiedClaimSet = originalClaimSet;
    
    CHECK(copiedClaimSet.token != nullptr);
    CHECK(copiedClaimSet.token->core.iss == "test-issuer");
}

TEST_CASE("ClaimSetWithComposite") {
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    
    auto composite = createOrFromTokens({token1, token2});
    ClaimSet claimSet(std::move(composite));
    
    CHECK(claimSet.hasComposite());
    CHECK_FALSE(claimSet.token != nullptr);
}

TEST_CASE("ComplexCompositeWithMultipleAndClaims") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    // Create tokens with different validity states
    auto validToken1 = createValidToken("valid-issuer-1");
    auto validToken2 = createValidToken("valid-issuer-2");  
    auto validToken3 = createValidToken("valid-issuer-3");
    auto expiredToken1 = createExpiredToken();
    auto expiredToken2 = createExpiredToken();
    
    // Create multiple AND composites - some should work, some shouldn't
    auto workingAnd1 = createAndFromTokens({validToken1, validToken2}); // Should work
    auto workingAnd2 = createAndFromTokens({validToken2, validToken3}); // Should work  
    auto failingAnd1 = createAndFromTokens({validToken1, expiredToken1}); // Should fail
    auto failingAnd2 = createAndFromTokens({expiredToken1, expiredToken2}); // Should fail
    
    // Create main token with OR composite containing multiple AND composites
    auto mainToken = createValidToken("main-issuer");
    auto orComposite = std::make_unique<OrClaim>();
    
    // Add working AND composites - at least one should make OR succeed
    ClaimSet workingClaimSet1(std::move(workingAnd1));
    ClaimSet workingClaimSet2(std::move(workingAnd2));
    ClaimSet failingClaimSet1(std::move(failingAnd1));
    ClaimSet failingClaimSet2(std::move(failingAnd2));
    
    orComposite->addClaimSet(workingClaimSet1);  
    orComposite->addClaimSet(failingClaimSet1); 
    orComposite->addClaimSet(workingClaimSet2);
    orComposite->addClaimSet(failingClaimSet2);
    
    auto tokenWithComplexComposite = mainToken.withOrComposite(std::move(orComposite));
    
    // Should succeed because OR contains working AND composites
    REQUIRE_NOTHROW(validator.validate(tokenWithComplexComposite));
}

TEST_CASE("ComplexCompositeWithAllFailingAndClaims") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto validToken = createValidToken("valid-issuer");
    auto expiredToken1 = createExpiredToken();
    auto expiredToken2 = createExpiredToken();
    auto expiredToken3 = createExpiredToken();
    
    // Create multiple failing AND composites
    auto failingAnd1 = createAndFromTokens({validToken, expiredToken1}); 
    auto failingAnd2 = createAndFromTokens({expiredToken1, expiredToken2});
    auto failingAnd3 = createAndFromTokens({validToken, expiredToken3});
    
    auto mainToken = createValidToken("main-issuer");
    auto orComposite = std::make_unique<OrClaim>();
    
    ClaimSet failingClaimSet1(std::move(failingAnd1));
    ClaimSet failingClaimSet2(std::move(failingAnd2));
    ClaimSet failingClaimSet3(std::move(failingAnd3));
    
    orComposite->addClaimSet(failingClaimSet1);
    orComposite->addClaimSet(failingClaimSet2);  
    orComposite->addClaimSet(failingClaimSet3);
    
    auto tokenWithFailingComposite = mainToken.withOrComposite(std::move(orComposite));
    
    // Should fail because all AND composites fail
    REQUIRE_THROWS_AS(validator.validate(tokenWithFailingComposite), InvalidClaimValueError);
}

TEST_CASE("ComplexCompositeWithMultipleOrClaims") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    // Create mix of valid and expired tokens
    auto validToken1 = createValidToken("valid-1");
    auto validToken2 = createValidToken("valid-2");
    auto validToken3 = createValidToken("valid-3");
    auto expiredToken1 = createExpiredToken();
    auto expiredToken2 = createExpiredToken();
    auto expiredToken3 = createExpiredToken();
    
    // Create multiple OR composites with different success patterns
    auto workingOr1 = createOrFromTokens({validToken1, expiredToken1}); // Should work (has valid)
    auto workingOr2 = createOrFromTokens({expiredToken2, validToken2}); // Should work (has valid)
    auto failingOr1 = createOrFromTokens({expiredToken1, expiredToken2}); // Should fail (all expired)
    auto workingOr3 = createOrFromTokens({validToken3, validToken1}); // Should work (all valid)
    
    // Create AND composite containing these OR composites
    auto mainToken = createValidToken("main-issuer");
    auto andComposite = std::make_unique<AndClaim>();
    
    ClaimSet workingOrClaimSet1(std::move(workingOr1));
    ClaimSet workingOrClaimSet2(std::move(workingOr2)); 
    ClaimSet workingOrClaimSet3(std::move(workingOr3));
    ClaimSet failingOrClaimSet1(std::move(failingOr1));
    
    // Add working OR composites - AND needs all to succeed
    andComposite->addClaimSet(workingOrClaimSet1);
    andComposite->addClaimSet(workingOrClaimSet2);
    andComposite->addClaimSet(workingOrClaimSet3);
    
    auto tokenWithWorkingComposite = mainToken.withAndComposite(std::move(andComposite));
    
    // Should succeed because AND contains only working OR composites
    REQUIRE_NOTHROW(validator.validate(tokenWithWorkingComposite));
}

TEST_CASE("ComplexCompositeWithMixedOrClaimsInAndContext") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto validToken1 = createValidToken("valid-1");
    auto expiredToken1 = createExpiredToken();
    auto expiredToken2 = createExpiredToken();
    
    // Create OR composites with different outcomes
    auto workingOr = createOrFromTokens({validToken1, expiredToken1}); // Works
    auto failingOr = createOrFromTokens({expiredToken1, expiredToken2}); // Fails
    
    // Create AND composite mixing working and failing OR composites
    auto mainToken = createValidToken("main-issuer");
    auto andComposite = std::make_unique<AndClaim>();
    
    ClaimSet workingOrClaimSet(std::move(workingOr));
    ClaimSet failingOrClaimSet(std::move(failingOr));
    
    andComposite->addClaimSet(workingOrClaimSet);
    andComposite->addClaimSet(failingOrClaimSet); // This will make the AND fail
    
    auto tokenWithMixedComposite = mainToken.withAndComposite(std::move(andComposite));
    
    // Should fail because AND requires ALL to succeed, but one OR fails
    REQUIRE_THROWS_AS(validator.validate(tokenWithMixedComposite), InvalidClaimValueError);
}

TEST_CASE("ComplexCompositeWithNorClaimsInsideOrClaims") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    // Create tokens for various combinations
    auto validToken1 = createValidToken("valid-1");
    auto validToken2 = createValidToken("valid-2");
    auto expiredToken1 = createExpiredToken();
    auto expiredToken2 = createExpiredToken();
    auto expiredToken3 = createExpiredToken();
    auto expiredToken4 = createExpiredToken();
    
    // Create NOR composites with different behaviors
    auto workingNor1 = createNorFromTokens({expiredToken1, expiredToken2}); // Works (all invalid)
    auto workingNor2 = createNorFromTokens({expiredToken3, expiredToken4}); // Works (all invalid)
    auto failingNor1 = createNorFromTokens({validToken1, expiredToken1}); // Fails (has valid)
    auto failingNor2 = createNorFromTokens({validToken2, validToken1}); // Fails (all valid)
    
    // Create OR composite containing these NOR composites
    auto mainToken = createValidToken("main-issuer");
    auto orComposite = std::make_unique<OrClaim>();
    
    ClaimSet workingNorClaimSet1(std::move(workingNor1));
    ClaimSet workingNorClaimSet2(std::move(workingNor2));
    ClaimSet failingNorClaimSet1(std::move(failingNor1));
    ClaimSet failingNorClaimSet2(std::move(failingNor2));
    
    // Add NOR composites to OR - should succeed if at least one NOR works
    orComposite->addClaimSet(workingNorClaimSet1); // This will work
    orComposite->addClaimSet(failingNorClaimSet1);
    orComposite->addClaimSet(failingNorClaimSet2);
    orComposite->addClaimSet(workingNorClaimSet2); // This will also work
    
    auto tokenWithNorInOr = mainToken.withOrComposite(std::move(orComposite));
    
    // Should succeed because OR contains working NOR composites
    REQUIRE_NOTHROW(validator.validate(tokenWithNorInOr));
}

TEST_CASE("ComplexCompositeWithOnlyFailingNorClaimsInsideOr") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto validToken1 = createValidToken("valid-1");
    auto validToken2 = createValidToken("valid-2");
    auto validToken3 = createValidToken("valid-3");
    auto expiredToken1 = createExpiredToken();
    
    // Create NOR composites that all fail (all have at least one valid token)
    auto failingNor1 = createNorFromTokens({validToken1, expiredToken1}); 
    auto failingNor2 = createNorFromTokens({validToken2, validToken3});
    auto failingNor3 = createNorFromTokens({validToken1, validToken2});
    
    // Create OR composite with only failing NOR composites
    auto mainToken = createValidToken("main-issuer");
    auto orComposite = std::make_unique<OrClaim>();
    
    ClaimSet failingNorClaimSet1(std::move(failingNor1));
    ClaimSet failingNorClaimSet2(std::move(failingNor2));
    ClaimSet failingNorClaimSet3(std::move(failingNor3));
    
    orComposite->addClaimSet(failingNorClaimSet1);
    orComposite->addClaimSet(failingNorClaimSet2);
    orComposite->addClaimSet(failingNorClaimSet3);
    
    auto tokenWithFailingNorInOr = mainToken.withOrComposite(std::move(orComposite));
    
    // Should fail because all NOR composites fail (all have valid tokens)
    REQUIRE_THROWS_AS(validator.validate(tokenWithFailingNorInOr), InvalidClaimValueError);
}

TEST_CASE("DeepNestedCompositeWithNorInsideOrInsideAnd") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto validToken1 = createValidToken("valid-1");
    auto validToken2 = createValidToken("valid-2");
    auto expiredToken1 = createExpiredToken();
    auto expiredToken2 = createExpiredToken();
    auto expiredToken3 = createExpiredToken();
    
    // Create NOR composites with different outcomes
    auto workingNor = createNorFromTokens({expiredToken1, expiredToken2}); // Works
    auto failingNor = createNorFromTokens({validToken1, expiredToken3}); // Fails
    
    // Create OR composite containing NOR composites
    auto orWithNor = std::make_unique<OrClaim>();
    ClaimSet workingNorClaimSet(std::move(workingNor));
    ClaimSet failingNorClaimSet(std::move(failingNor));
    orWithNor->addClaimSet(workingNorClaimSet); // This makes OR succeed
    orWithNor->addClaimSet(failingNorClaimSet);
    
    // Create another OR composite with regular tokens
    auto regularOr = createOrFromTokens({validToken2, expiredToken1}); // Works
    
    // Create AND composite containing both OR composites
    auto mainToken = createValidToken("main-issuer");
    auto andComposite = std::make_unique<AndClaim>();
    
    ClaimSet orWithNorClaimSet(std::move(orWithNor));
    ClaimSet regularOrClaimSet(std::move(regularOr));
    
    andComposite->addClaimSet(orWithNorClaimSet);
    andComposite->addClaimSet(regularOrClaimSet);
    
    auto deeplyNestedToken = mainToken.withAndComposite(std::move(andComposite));
    
    // Should succeed because both OR composites work
    // (first OR works due to working NOR, second OR works due to valid token)
    REQUIRE_NOTHROW(validator.validate(deeplyNestedToken));
    CHECK(deeplyNestedToken.composite.andClaim.value()->getDepth() == 3);
}

TEST_CASE("UltraComplexCompositeClaimCombinations") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    // Create a variety of tokens with different validity states
    auto valid1 = createValidToken("issuer-1");
    auto valid2 = createValidToken("issuer-2"); 
    auto valid3 = createValidToken("issuer-3");
    auto valid4 = createValidToken("issuer-4");
    auto expired1 = createExpiredToken();
    auto expired2 = createExpiredToken();
    auto expired3 = createExpiredToken();
    auto expired4 = createExpiredToken();
    
    // Layer 1: Create basic composites with mixed outcomes
    auto workingAnd1 = createAndFromTokens({valid1, valid2}); // Works
    auto failingAnd1 = createAndFromTokens({valid3, expired1}); // Fails
    auto workingOr1 = createOrFromTokens({valid4, expired2}); // Works
    auto failingOr1 = createOrFromTokens({expired3, expired4}); // Fails
    auto workingNor1 = createNorFromTokens({expired1, expired2}); // Works
    auto failingNor1 = createNorFromTokens({valid1, expired3}); // Fails
    
    // Layer 2: Combine into intermediate composites
    // Create OR containing working AND and failing NOR (should work due to AND)
    auto intermediateOr1 = std::make_unique<OrClaim>();
    ClaimSet workingAndClaimSet1(std::move(workingAnd1));
    ClaimSet failingNorClaimSet1(std::move(failingNor1));
    intermediateOr1->addClaimSet(workingAndClaimSet1);
    intermediateOr1->addClaimSet(failingNorClaimSet1);
    
    // Create AND containing working OR and working NOR (should work - all components work)
    auto intermediateAnd1 = std::make_unique<AndClaim>();
    ClaimSet workingOrClaimSet1(std::move(workingOr1));
    ClaimSet workingNorClaimSet1(std::move(workingNor1));
    intermediateAnd1->addClaimSet(workingOrClaimSet1);
    intermediateAnd1->addClaimSet(workingNorClaimSet1);
    
    // Create NOR containing failing AND and failing OR (should work - all components fail)
    auto intermediateNor1 = std::make_unique<NorClaim>();
    ClaimSet failingAndClaimSet1(std::move(failingAnd1));
    ClaimSet failingOrClaimSet1(std::move(failingOr1));
    intermediateNor1->addClaimSet(failingAndClaimSet1);
    intermediateNor1->addClaimSet(failingOrClaimSet1);
    
    // Layer 3: Final top-level composite
    // Create final OR containing all intermediate composites
    auto finalOrComposite = std::make_unique<OrClaim>();
    ClaimSet intermediateOrClaimSet1(std::move(intermediateOr1)); // Works
    ClaimSet intermediateAndClaimSet1(std::move(intermediateAnd1)); // Works
    ClaimSet intermediateNorClaimSet1(std::move(intermediateNor1)); // Works
    
    finalOrComposite->addClaimSet(intermediateOrClaimSet1);
    finalOrComposite->addClaimSet(intermediateAndClaimSet1);
    finalOrComposite->addClaimSet(intermediateNorClaimSet1);
    
    auto ultraComplexToken = createValidToken("ultra-complex-main")
        .withOrComposite(std::move(finalOrComposite));
    
    // Should succeed because all intermediate composites evaluate to true
    REQUIRE_NOTHROW(validator.validate(ultraComplexToken));
    CHECK(ultraComplexToken.composite.orClaim.value()->getDepth() == 3);
}

TEST_CASE("UltraComplexFailingCompositeClaimCombinations") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    // Create tokens for failure scenarios
    auto valid1 = createValidToken("valid-issuer-1");
    auto valid2 = createValidToken("valid-issuer-2");
    auto expired1 = createExpiredToken();
    auto expired2 = createExpiredToken();
    auto expired3 = createExpiredToken();
    auto expired4 = createExpiredToken();
    
    // Layer 1: Create composites that will all fail
    auto failingAnd1 = createAndFromTokens({valid1, expired1}); // Fails
    auto failingAnd2 = createAndFromTokens({expired2, expired3}); // Fails  
    auto failingOr1 = createOrFromTokens({expired1, expired2}); // Fails
    auto failingOr2 = createOrFromTokens({expired3, expired4}); // Fails
    auto failingNor1 = createNorFromTokens({valid1, valid2}); // Fails (has valid tokens)
    
    // Layer 2: Combine failing components
    // Create OR with failing AND and failing NOR (should fail - both fail)
    auto intermediateOr1 = std::make_unique<OrClaim>();
    ClaimSet failingAndClaimSet1(std::move(failingAnd1));
    ClaimSet failingNorClaimSet1(std::move(failingNor1));
    intermediateOr1->addClaimSet(failingAndClaimSet1);
    intermediateOr1->addClaimSet(failingNorClaimSet1);
    
    // Create AND with failing OR components (should fail - not all succeed) 
    auto intermediateAnd1 = std::make_unique<AndClaim>();
    ClaimSet failingOrClaimSet1(std::move(failingOr1));
    ClaimSet failingOrClaimSet2(std::move(failingOr2));
    intermediateAnd1->addClaimSet(failingOrClaimSet1);
    intermediateAnd1->addClaimSet(failingOrClaimSet2);
    
    // Layer 3: Create final AND requiring all intermediate to succeed
    auto finalAndComposite = std::make_unique<AndClaim>();
    ClaimSet intermediateOrClaimSet1(std::move(intermediateOr1)); // Fails
    ClaimSet intermediateAndClaimSet1(std::move(intermediateAnd1)); // Fails
    ClaimSet failingAndClaimSet2(std::move(failingAnd2)); // Fails
    
    finalAndComposite->addClaimSet(intermediateOrClaimSet1);
    finalAndComposite->addClaimSet(intermediateAndClaimSet1);
    finalAndComposite->addClaimSet(failingAndClaimSet2);
    
    auto ultraComplexFailingToken = createValidToken("ultra-complex-failing-main")
        .withAndComposite(std::move(finalAndComposite));
    
    // Should fail because AND requires all to succeed, but all intermediates fail
    REQUIRE_THROWS_AS(validator.validate(ultraComplexFailingToken), InvalidClaimValueError);
}

TEST_CASE("MixedSuccessFailureUltraComplexScenario") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto valid1 = createValidToken("v1");
    auto valid2 = createValidToken("v2");
    auto valid3 = createValidToken("v3");
    auto expired1 = createExpiredToken();
    auto expired2 = createExpiredToken();
    auto expired3 = createExpiredToken();
    
    // Create mixed success/failure components
    auto successAnd = createAndFromTokens({valid1, valid2}); // Success
    auto failureAnd = createAndFromTokens({valid3, expired1}); // Failure
    auto successOr = createOrFromTokens({valid1, expired2}); // Success
    auto failureOr = createOrFromTokens({expired1, expired2}); // Failure
    auto successNor = createNorFromTokens({expired2, expired3}); // Success
    auto failureNor = createNorFromTokens({valid2, expired1}); // Failure
    
    // Layer 2: Strategic combinations
    // OR with success + failures = SUCCESS
    auto layer2Success = std::make_unique<OrClaim>();
    ClaimSet successAndClaimSet(std::move(successAnd));
    ClaimSet failureNorClaimSet(std::move(failureNor));
    layer2Success->addClaimSet(successAndClaimSet); // This makes OR succeed
    layer2Success->addClaimSet(failureNorClaimSet);
    
    // AND with success + failure = FAILURE
    auto layer2Failure = std::make_unique<AndClaim>();
    ClaimSet successOrClaimSet(std::move(successOr));
    ClaimSet failureAndClaimSet(std::move(failureAnd));
    layer2Failure->addClaimSet(successOrClaimSet);
    layer2Failure->addClaimSet(failureAndClaimSet); // This makes AND fail
    
    // NOR with success + failure = FAILURE (because success exists)
    auto layer2Failure2 = std::make_unique<NorClaim>(); 
    ClaimSet successNorClaimSet(std::move(successNor));
    ClaimSet failureOrClaimSet(std::move(failureOr));
    layer2Failure2->addClaimSet(successNorClaimSet); // This makes NOR fail
    layer2Failure2->addClaimSet(failureOrClaimSet);
    
    // Layer 3: Final OR with mixed layer 2 results
    auto finalOr = std::make_unique<OrClaim>();
    ClaimSet layer2SuccessClaimSet(std::move(layer2Success)); // SUCCESS
    ClaimSet layer2FailureClaimSet1(std::move(layer2Failure)); // FAILURE
    ClaimSet layer2FailureClaimSet2(std::move(layer2Failure2)); // FAILURE
    
    finalOr->addClaimSet(layer2SuccessClaimSet); // This makes final OR succeed
    finalOr->addClaimSet(layer2FailureClaimSet1);
    finalOr->addClaimSet(layer2FailureClaimSet2);
    
    auto mixedComplexToken = createValidToken("mixed-complex-main")
        .withOrComposite(std::move(finalOr));
    
    // Should succeed because final OR has at least one successful component
    REQUIRE_NOTHROW(validator.validate(mixedComplexToken));
    CHECK(mixedComplexToken.composite.orClaim.value()->getDepth() == 3);
}

TEST_CASE("CompileTimeTypedOrComposite") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    
    auto orComposite = composite_utils::createOrCompositeTyped(ClaimSet(token1), ClaimSet(token2));
    
    CHECK(orComposite.operation == CompositeOperator::OR);
    CHECK(orComposite.claims.size() == 2);
    CHECK(orComposite.getDepth() == 1);
    CHECK(orComposite.evaluate(validator) == true);
}

TEST_CASE("CompileTimeTypedAndComposite") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    
    auto andComposite = composite_utils::createAndCompositeTyped(ClaimSet(token1), ClaimSet(token2));
    
    CHECK(andComposite.operation == CompositeOperator::AND);
    CHECK(andComposite.claims.size() == 2);
    CHECK(andComposite.getDepth() == 1);
    CHECK(andComposite.evaluate(validator) == true);
}

TEST_CASE("CompileTimeTypedNorComposite") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto expired1 = createExpiredToken();
    auto expired2 = createExpiredToken();
    
    auto norComposite = composite_utils::createNorCompositeTyped(ClaimSet(expired1), ClaimSet(expired2));
    
    CHECK(norComposite.operation == CompositeOperator::NOR);
    CHECK(norComposite.claims.size() == 2);
    CHECK(norComposite.getDepth() == 1);
    CHECK(norComposite.evaluate(validator) == true);
}

TEST_CASE("CompileTimeTypedNestedComposite") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto token1 = createValidToken("issuer1");
    auto token2 = createValidToken("issuer2");
    auto token3 = createValidToken("issuer3");
    
    auto innerOr = composite_utils::createOrCompositeTyped(ClaimSet(token1), ClaimSet(token2));
    auto outerAnd = composite_utils::createAndCompositeTyped(ClaimSet(token3));
    
    outerAnd.addClaimSet(ClaimSet(std::make_unique<OrClaim>(std::move(innerOr))));
    
    CHECK(outerAnd.operation == CompositeOperator::AND);
    CHECK(outerAnd.getDepth() == 2);
    CHECK(outerAnd.evaluate(validator) == true);
}

TEST_CASE("CompileTimeTypedCompositeFactory") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto token1 = createValidToken("factory1");
    auto token2 = createValidToken("factory2");
    
    auto orFactory = composite_utils::OrFactory::create(ClaimSet(token1), ClaimSet(token2));
    auto andFactory = composite_utils::AndFactory::create(ClaimSet(token1), ClaimSet(token2));
    
    CHECK(orFactory.operation == CompositeOperator::OR);
    CHECK(andFactory.operation == CompositeOperator::AND);
    CHECK(orFactory.evaluate(validator) == true);
    CHECK(andFactory.evaluate(validator) == true);
}

TEST_CASE("CompileTimeTypedCompositeWithMemoryPool") {
    auto validator = CatTokenValidator().withClockSkewTolerance(60);
    
    auto token1 = createValidToken("pool1");
    auto token2 = createValidToken("pool2");
    
    OrClaim pooledOr;
    pooledOr.addToken(token1);
    pooledOr.addToken(token2);
    CHECK(pooledOr.claims.size() == 2);
    CHECK(pooledOr.evaluate(validator) == true);
    
    AndClaim pooledAnd;
    pooledAnd.addToken(token1);
    pooledAnd.addToken(token2);
    CHECK(pooledAnd.claims.size() == 2);
    CHECK(pooledAnd.evaluate(validator) == true);
}