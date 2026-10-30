#include "storage/file_manager.h"

#include "storage/block_crypto.h"
#include <limits>
#include <stdexcept>
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace storage
{

    FileManager::FileManager(
        BlockStore &store,
        const crypto::Key256 &encryption_key)
        : FileManager(
              store,
              encryption_key,
              crypto::generate_key()) {}

    FileManager::FileManager(
        BlockStore &store,
        const crypto::Key256 &encryption_key,
        const crypto::Key256 &id_key)
        : store_(store),
          encryption_key_(encryption_key),
          candidate_generator_(id_key) {}

    void FileManager::store_file(
        const std::string &file_id,
        const std::string &data,
        std::uint64_t initial_version)
    {
        if (file_id.empty())
        {
            throw std::invalid_argument("File identifier cannot be empty");
        }

        if (file_blocks_.count(file_id))
        {
            throw std::runtime_error("File already exists");
        }

        const auto hash = crypto::sha256(file_id);

        const std::size_t block_count = std::max<std::size_t>(
            1, (data.size() + BLOCK_SIZE - 1) / BLOCK_SIZE);

        std::vector<std::size_t> allocated;

        try
        {
            // Allocate every required block first.
            for (std::size_t i = 0; i < block_count; ++i)
            {
                allocated.push_back(store_.allocate());
            }

            // Populate and encrypt each block.
            for (std::size_t i = 0; i < block_count; ++i)
            {
                StorageBlock &block = store_.get(allocated[i]);

                block.file_id_hash = hash;
                block.version = initial_version;
                block.is_first_block = (i == 0);
                block.file_size = (i == 0) ? data.size() : 0;

                const std::size_t offset = i * BLOCK_SIZE;
                const std::size_t length =
                    offset < data.size()
                        ? std::min(BLOCK_SIZE, data.size() - offset)
                        : 0;

                block.contents.assign(
                    data.begin() + offset,
                    data.begin() + offset + length);

                crypt_block(block, encryption_key_);
            }

            file_blocks_[file_id] = std::move(allocated);
        }
        catch (...)
        {
            for (std::size_t index : allocated)
            {
                store_.release(index);
            }
            throw;
        }
    }

    std::string FileManager::retrieve_file(
        const std::string &file_id) const
    {
        const auto it = file_blocks_.find(file_id);

        if (it == file_blocks_.end())
        {
            throw std::runtime_error("File not found");
        }

        std::string result;
        std::uint64_t original_size = 0;

        for (std::size_t i = 0; i < it->second.size(); ++i)
        {
            StorageBlock block = store_.get(it->second[i]);

            crypt_block(block, encryption_key_);

            if (i == 0)
            {
                original_size = block.file_size;
            }

            result.append(
                block.contents.begin(),
                block.contents.end());
        }

        if (result.size() > original_size)
        {
            result.resize(static_cast<std::size_t>(original_size));
        }

        return result;
    }

    void FileManager::delete_file(const std::string &file_id)
    {
        const auto it = file_blocks_.find(file_id);

        if (it == file_blocks_.end())
        {
            throw std::runtime_error("File not found");
        }

        for (std::size_t index : it->second)
        {
            store_.release(index);
        }

        file_blocks_.erase(it);
    }

    void FileManager::update_file(
        const std::string &file_id,
        const std::string &new_data)
    {
        const auto it = file_blocks_.find(file_id);

        if (it == file_blocks_.end())
        {
            throw std::runtime_error("File not found");
        }

        // Read the current version before releasing the old blocks.
        const std::uint64_t current_version =
            store_.get(it->second.front()).version;

        if (current_version == std::numeric_limits<std::uint64_t>::max())
        {
            throw std::runtime_error("File version limit reached");
        }

        const std::uint64_t next_version = current_version + 1;

        // Release the existing blocks.
        const auto old_blocks = it->second;

        for (std::size_t index : old_blocks)
        {
            store_.release(index);
        }

        file_blocks_.erase(file_id);

        // Store the replacement using the incremented version.
        try
        {
            store_file(file_id, new_data, next_version);
        }
        catch (...)
        {
            throw std::runtime_error(
                "File update failed; previous file could not be restored");
        }
    }
} // namespace storage