#ifndef BLOCK_STORE_H
#define BLOCK_STORE_H

#include "storage/storage_block.h"

#include <cstddef>
#include <vector>

namespace storage {

class BlockStore {
public:
    explicit BlockStore(std::size_t capacity);

    // Find a free block and reserve it.
    std::size_t allocate();

    // Access a block by index.
    StorageBlock& get(std::size_t index);
    const StorageBlock& get(std::size_t index) const;

    // Mark a block as free.
    void release(std::size_t index);

    std::size_t capacity() const;
    std::size_t free_count() const;

private:
    std::vector<StorageBlock> blocks_;
    std::vector<bool> allocated_;
};

}  // namespace storage

#endif