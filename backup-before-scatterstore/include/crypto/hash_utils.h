#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include <array>
#include <string>

namespace crypto {

using Hash256 = std::array<unsigned char, 32>;

// Compute SHA-256 of a file identifier.
Hash256 sha256(const std::string& input);

}  // namespace crypto

#endif