#include "storage/candidate_generator.h"

#include "crypto/aes_prf.h"
#include "crypto/hash_utils.h"

#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace storage {
namespace {

std::uint64_t read_u64(
    const unsigned char* bytes
) {
    std::uint64_t value = 0;

    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8) | bytes[i];
    }

    return value;
}

std::uint64_t uniform_below(
    const crypto::Key256& key,
    const crypto::Hash256& seed,
    std::uint64_t bound,
    std::uint64_t& counter
) {
    if (bound == 0) {
        throw std::invalid_argument("Bound must be positive");
    }

    const std::uint64_t threshold =
        static_cast<std::uint64_t>(-bound) % bound;

    while (true) {
        std::array<unsigned char, 16> input{};

        // Use the first 8 bytes of the seed as a domain-specific prefix.
        for (std::size_t i = 0; i < 8; ++i) {
            input[i] = seed[i];
        }

        // Counter distinguishes PRF calls.
        for (std::size_t i = 0; i < 8; ++i) {
            input[8 + i] = static_cast<unsigned char>(
                (counter >> (56 - 8 * i)) & 0xFF
            );
        }

        if (counter == std::numeric_limits<std::uint64_t>::max()) {
            throw std::runtime_error("Candidate PRF counter exhausted");
        }
        ++counter;

        const auto output = crypto::aes_prf_block(key, input);
        const std::uint64_t value = read_u64(output.data());

        if (value >= threshold) {
            return value % bound;
        }
    }
}

}  // namespace

CandidateGenerator::CandidateGenerator(
    const crypto::Key256& id_key
)
    : id_key_(id_key) {}

std::vector<std::size_t> CandidateGenerator::generate(
    const std::string& file_id,
    std::size_t capacity,
    std::size_t count
) const {
    if (file_id.empty()) {
        throw std::invalid_argument("File identifier cannot be empty");
    }

    if (capacity == 0 || count > capacity) {
        throw std::invalid_argument(
            "Capacity must be positive and count cannot exceed capacity"
        );
    }

    // Hash arbitrary-length identifiers to a fixed-length seed.
    const auto seed = crypto::sha256(file_id);

    // Derive a file-specific seed with the ID key.
    std::array<unsigned char, 16> seed_input{};
    for (std::size_t i = 0; i < 16; ++i) {
        seed_input[i] = seed[i];
    }

    const auto derived = crypto::aes_prf_block(id_key_, seed_input);
    crypto::Hash256 file_seed{};
    for (std::size_t i = 0; i < derived.size(); ++i) {
        file_seed[i] = derived[i];
    }

    std::vector<std::size_t> indices(capacity);
    for (std::size_t i = 0; i < capacity; ++i) {
        indices[i] = i;
    }

    std::uint64_t counter = 0;

    // Deterministic partial Fisher-Yates selection.
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t remaining =
            static_cast<std::uint64_t>(capacity - i);

        const std::uint64_t offset = uniform_below(
            id_key_, file_seed, remaining, counter
        );

        const std::size_t j =
            i + static_cast<std::size_t>(offset);

        std::swap(indices[i], indices[j]);
    }

    indices.resize(count);
    return indices;
}

}  // namespace storage
