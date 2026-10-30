#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include "crypto/crypto_utils.h"
#include "storage/block_store.h"

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
namespace storage {

class FileManager {
public:
    explicit FileManager(
        BlockStore& store,
        const crypto::Key256& encryption_key
    );

    void delete_file(const std::string& file_id);
    void update_file(
        const std::string& file_id,
        const std::string& new_data
    );
    void store_file(
        const std::string& file_id,
        const std::string& data,
        std::uint64_t initial_version = 0
    );

    std::string retrieve_file(const std::string& file_id) const;

private:
    BlockStore& store_;
    crypto::Key256 encryption_key_;

    std::unordered_map<std::string, std::vector<std::size_t>> file_blocks_;

    static constexpr std::size_t BLOCK_SIZE = 16;
};

}  // namespace storage

#endif