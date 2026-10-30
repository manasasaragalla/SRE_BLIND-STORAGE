#ifndef STORAGE_BLOCK_H
#define STORAGE_BLOCK_H

#include "crypto/hash_utils.h"

#include <cstdint>
#include <vector>

namespace storage {

struct StorageBlock {
    // Block location and version.
    // The version remains unencrypted.
    std::uint64_t index = 0;
    std::uint64_t version = 0;

    // Logical metadata.
    // These fields are cleared after encryption because their values
    // are stored inside the encrypted payload.
    crypto::Hash256 file_id_hash{};

    std::uint64_t file_size = 0;
    bool is_first_block = false;
    bool encrypted = false;
    // Plaintext file data before encryption.
    // Encrypted representation after encryption.
    std::vector<unsigned char> contents;
};

}  // namespace storage

#endif