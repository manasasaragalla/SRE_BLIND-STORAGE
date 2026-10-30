#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {

using Key256 = std::array<unsigned char, 32>;
using Hash256 = std::array<unsigned char, 32>;

// Generate a cryptographically secure random key.
Key256 generate_key();

// Generate cryptographically secure random bytes.
std::vector<unsigned char> random_bytes(std::size_t size);

// Compute SHA-256 of the supplied data.
Hash256 sha256(const std::vector<unsigned char>& data);

// Compute HMAC-SHA-256.
Hash256 hmac_sha256(
    const Key256& key,
    const std::vector<unsigned char>& data
);

// Convert bytes to hexadecimal for debugging and display.
std::string to_hex(const unsigned char* data, std::size_t size);

}  // namespace crypto

#endif