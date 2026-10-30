#include <algorithm>
#include "storage/block_store.h"
#include <stdexcept>

namespace storage {

BlockStore::BlockStore(std::size_t capacity)
    : blocks_(capacity), allocated_(capacity, false) {
    for (std::size_t i = 0; i < capacity; ++i) {
        blocks_[i].index = i;
    }
}

std::size_t BlockStore::allocate() {
    for (std::size_t i = 0; i < blocks_.size(); ++i) {
        const bool hash_is_zero = std::all_of(
            blocks_[i].file_id_hash.begin(),
            blocks_[i].file_id_hash.end(),
            [](unsigned char byte) {
                return byte == 0;
            }
        );

        if (!allocated_[i] && hash_is_zero) {
            allocated_[i] = true;
            return i;
        }
    }

    throw std::runtime_error("No free storage blocks available");
}

StorageBlock& BlockStore::get(std::size_t index) {
    if (index >= blocks_.size() || !allocated_[index]) {
        throw std::out_of_range("Block is invalid or not allocated");
    }

    return blocks_[index];
}

const StorageBlock& BlockStore::get(std::size_t index) const {
    if (index >= blocks_.size() || !allocated_[index]) {
        throw std::out_of_range("Block is invalid or not allocated");
    }

    return blocks_[index];
}

void BlockStore::release(std::size_t index) {
    if (index >= blocks_.size() || !allocated_[index]) {
        throw std::out_of_range(
            "Cannot release an invalid or free block"
        );
    }

    blocks_[index] = StorageBlock{};
    blocks_[index].index = index;
    allocated_[index] = false;
}

std::size_t BlockStore::capacity() const {
    return blocks_.size();
}

std::size_t BlockStore::free_count() const {
    std::size_t count = 0;

    for (bool allocated : allocated_) {
        if (!allocated) {
            ++count;
        }
    }

    return count;
}

}  // namespace storage