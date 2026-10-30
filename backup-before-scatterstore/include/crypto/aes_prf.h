#ifndef AES_PRF_H
#define AES_PRF_H

#include "crypto/crypto_utils.h"

#include <array>
#include <cstdint>

namespace crypto {

using PrfOutput = std::array<unsigned char, 16>;

// Evaluate AES-256 on one 128-bit input block.
// This is the AES primitive used to build the paper-specific PRF.
PrfOutput aes_prf_block(
    const Key256& key,
    const std::array<unsigned char, 16>& input
);

}  // namespace crypto

#endif