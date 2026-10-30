#include "storage/block_crypto.h"
#include "crypto/aes_prf.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace storage {
namespace {

constexpr std::size_t HASH_SIZE = 32;
constexpr std::size_t SIZE_FIELD_SIZE = 8;
constexpr std::size_t FLAG_SIZE = 1;
constexpr std::size_t DATA_SIZE = 16;

constexpr std::size_t SERIALIZED_SIZE =
    HASH_SIZE + SIZE_FIELD_SIZE + FLAG_SIZE + DATA_SIZE;

void write_u64(
    std::vector<unsigned char>& output,
    std::size_t offset,
    std::uint64_t value
) {
    for (std::size_t i = 0; i < 8; ++i) {
        output[offset + i] = static_cast<unsigned char>(
            (value >> (56 - 8 * i)) & 0xFF
        );
    }
}

std::uint64_t read_u64(
    const std::vector<unsigned char>& input,
    std::size_t offset
) {
    std::uint64_t value = 0;

    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8) | input[offset + i];
    }

    return value;
}

bool has_zero_hash(const crypto::Hash256& hash) {
    return std::all_of(
        hash.begin(),
        hash.end(),
        [](unsigned char byte) {
            return byte == 0;
        }
    );
}

void apply_mask(
    std::vector<unsigned char>& payload,
    std::uint64_t version,
    std::uint64_t block_index,
    const crypto::Key256& key
) {
    if (block_index > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error(
            "Block index exceeds the supported 32-bit range"
        );
    }

    std::size_t offset = 0;
    std::uint64_t counter = 0;

    while (offset < payload.size()) {
        if (counter > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("Block payload is too large");
        }

        std::array<unsigned char, 16> input{};

        for (std::size_t i = 0; i < 8; ++i) {
            input[i] = static_cast<unsigned char>(
                (version >> (56 - 8 * i)) & 0xFF
            );
        }

        const auto index = static_cast<std::uint32_t>(block_index);

        for (std::size_t i = 0; i < 4; ++i) {
            input[8 + i] = static_cast<unsigned char>(
                (index >> (24 - 8 * i)) & 0xFF
            );
        }

        const auto ctr = static_cast<std::uint32_t>(counter);

        for (std::size_t i = 0; i < 4; ++i) {
            input[12 + i] = static_cast<unsigned char>(
                (ctr >> (24 - 8 * i)) & 0xFF
            );
        }

        const auto mask = crypto::aes_prf_block(key, input);

        for (std::size_t i = 0;
             i < mask.size() && offset < payload.size();
             ++i, ++offset) {
            payload[offset] ^= mask[i];
        }

        ++counter;
    }
}

}  // namespace

void crypt_block(
    StorageBlock& block,
    const crypto::Key256& key
) {
    // Explicit state: never infer encryption state from payload contents.
    if (block.encrypted) {
        if (block.contents.size() != SERIALIZED_SIZE) {
            throw std::runtime_error(
                "Invalid encrypted block payload size"
            );
        }

        apply_mask(
            block.contents,
            block.version,
            block.index,
            key
        );

        std::copy_n(
            block.contents.begin(),
            HASH_SIZE,
            block.file_id_hash.begin()
        );

        block.file_size = read_u64(block.contents, HASH_SIZE);

        block.is_first_block =
            block.contents[HASH_SIZE + SIZE_FIELD_SIZE] != 0;

        block.contents = std::vector<unsigned char>(
            block.contents.begin() +
                HASH_SIZE + SIZE_FIELD_SIZE + FLAG_SIZE,
            block.contents.end()
        );

        block.encrypted = false;
        return;
    }

    // Encrypting a plaintext block.
    if (block.contents.size() > DATA_SIZE) {
        throw std::runtime_error(
            "Plaintext data exceeds the supported block size"
        );
    }

    if (has_zero_hash(block.file_id_hash)) {
        throw std::runtime_error(
            "A zero file ID hash is reserved for free blocks"
        );
    }

    std::vector<unsigned char> payload(SERIALIZED_SIZE, 0);

    std::copy(
        block.file_id_hash.begin(),
        block.file_id_hash.end(),
        payload.begin()
    );

    write_u64(payload, HASH_SIZE, block.file_size);

    payload[HASH_SIZE + SIZE_FIELD_SIZE] =
        block.is_first_block ? 1 : 0;

    std::copy(
        block.contents.begin(),
        block.contents.end(),
        payload.begin() +
            HASH_SIZE + SIZE_FIELD_SIZE + FLAG_SIZE
    );

    apply_mask(payload, block.version, block.index, key);

    block.contents = std::move(payload);

    // Clear metadata that is now protected inside the payload.
    block.file_id_hash.fill(0);
    block.file_size = 0;
    block.is_first_block = false;
    block.encrypted = true;
}

}  // namespace storage