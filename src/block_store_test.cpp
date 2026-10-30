#include "storage/block_store.h"

#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    try {
        storage::BlockStore store(10);

        // Reserve block 0 using the original allocator.
        const auto first = store.allocate();

        if (first != 0) {
            throw std::runtime_error("Unexpected first allocation");
        }

        // The allocator should skip occupied block 0 and choose block 5.
        const auto chosen = store.allocate_from_candidates({0, 5, 7});

        if (chosen != 5) {
            throw std::runtime_error("Wrong candidate block selected");
        }

        // All supplied candidates are occupied, so allocation must fail.
        bool failed_as_expected = false;

        try {
            store.allocate_from_candidates({0, 5});
        } catch (const std::runtime_error&) {
            failed_as_expected = true;
        }

        if (!failed_as_expected) {
            throw std::runtime_error(
                "Expected failure when no candidate was free"
            );
        }

        // Invalid candidate indices must be rejected.
        bool invalid_rejected = false;

        try {
            store.allocate_from_candidates({10});
        } catch (const std::out_of_range&) {
            invalid_rejected = true;
        }

        if (!invalid_rejected) {
            throw std::runtime_error(
                "Out-of-range candidate was not rejected"
            );
        }

        std::cout << "Candidate allocation test passed!\n";
        std::cout << "Occupied block skipped test passed!\n";
        std::cout << "No-free-candidate test passed!\n";
        std::cout << "Invalid-index test passed!\n";
    } catch (const std::exception& error) {
        std::cerr << "Test failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
