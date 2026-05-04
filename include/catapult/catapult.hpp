/**
 * @file catapult.hpp
 * @brief Main umbrella header for the Catapult library
 *
 * Include this single header to get access to all Catapult functionality.
 * For minimal builds, use catapult_minimal.hpp instead.
 */

#pragma once

// Core token functionality
#include "base64.hpp"
#include "claims.hpp"
#include "crypto.hpp"
#include "cwt.hpp"
#include "error.hpp"
#include "token.hpp"
#include "validator.hpp"

// MOQT support
#include "moqt_claims.hpp"

// DPoP support
#include "dpop.hpp"

// Composite claims
#include "composite.hpp"

// Token factory utilities are included in token.hpp

// URI utilities
#include "uri.hpp"

// Optional JSON serialization (only when enabled)
#ifdef CATAPULT_ENABLE_JSON
#include "json_serialization.hpp"
#include "jwk.hpp"
#endif
