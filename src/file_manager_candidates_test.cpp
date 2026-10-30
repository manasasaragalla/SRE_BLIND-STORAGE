#include "storage/file_manager.h"

#include <iostream>
#include <stdexcept>

int main() {
    try {
        crypto::Key256 encryption_key{};
        crypto::Key256 id_key{};

        for (std::size_t i = 0; i < 32; ++i) {
            encryption_key[i] = static_cast<unsigned char>(i + 1);
            id_key[i] = static_cast<unsigned char>(100 + i);
        }

        storage::BlockStore store(100);
        storage::FileManager manager(store, encryption_key, id_key);

        const std::string file_id = "candidate-test-file";
        const std::string data =
            "Testing candidate-based storage and retrieval.";

        manager.store_file_with_candidates(file_id, data, 7);

        const std::string recovered = manager.retrieve_file(file_id);

        if (recovered != data) {
            throw std::runtime_error("Retrieved content does not match");
        }

        std::cout << "Candidate-based storage test passed!\n";
        std::cout << "Content retrieval test passed!\n";
        std::cout << "Recovered content: " << recovered << '\n';
        std::cout << "Free blocks remaining: "
                  << store.free_count() << '\n';
    } catch (const std::exception& error) {
        std::cerr << "Test failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
