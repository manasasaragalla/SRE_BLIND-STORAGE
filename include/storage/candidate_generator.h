#ifndef CANDIDATE_GENERATOR_H
#define CANDIDATE_GENERATOR_H

#include "crypto/crypto_utils.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace storage {

class CandidateGenerator {
public:
    explicit CandidateGenerator(const crypto::Key256& id_key);

    // Generate an ordered, deterministic list of distinct block indices.
    // The returned indices are in [0, capacity).
    std::vector<std::size_t> generate(
        const std::string& file_id,
        std::size_t capacity,
        std::size_t count
    ) const;

private:
    crypto::Key256 id_key_;
};

}  // namespace storage

#endif
