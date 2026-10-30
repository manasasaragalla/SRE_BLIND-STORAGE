#ifndef STORAGE_BLOCK_H
#define STORAGE_BLOCK_H

#include <cstdint>
#include <vector>

namespace storage {

struct StorageBlock {
    std::uint64_t index = 0;

    // Unencrypted version number; initialized to 0.
    std::uint64_t version = 0;

    // H(id_f). An all-zero value identifies a free block.
    std::vector<unsigned char> file_id_hash;

    // Present only in the first block of a file.
    std::uint64_t file_size = 0;
    bool is_first_block = false;

    // Remaining block data, encrypted using the XOR-mask construction.
    std::vector<unsigned char> contents;
};

}  // namespace storage

#endif