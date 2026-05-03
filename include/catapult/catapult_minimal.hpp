/**
 * @file catapult_minimal.hpp
 * @brief Minimal umbrella header for core CAT/CWT functionality
 *
 * Include this header for lightweight integrations that only need
 * basic token generation and validation without MOQT or DPoP support.
 */

#pragma once

// Core token functionality
#include "token.hpp"
#include "claims.hpp"
#include "cwt.hpp"
#include "crypto.hpp"
#include "validator.hpp"
#include "error.hpp"
#include "base64.hpp"
