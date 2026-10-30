#include "crypto/crypto_utils.h"
#include "storage/file_manager.h"

#include <iostream>
#include <stdexcept>
#include <string>

int main() {
    try {
        storage::BlockStore store(30);
        const auto key = crypto::generate_key();
        storage::FileManager manager(store, key);

        manager.store_file("file_001", "Original file contents.");

        const std::string updated =
            "Updated confidential file contents.";

        manager.update_file("file_001", updated);

        const std::string recovered =
            manager.retrieve_file("file_001");

        if (recovered != updated) {
            throw std::runtime_error("Updated content mismatch");
        }

        std::cout << "File update passed!\n";
        std::cout << "Updated content retrieval passed!\n";
        std::cout << "Updated block version: "
          << store.get(0).version << '\n';
        std::cout << "Recovered: " << recovered << '\n';
        std::cout << "Free blocks remaining: "
                  << store.free_count() << '\n';

    } catch (const std::exception& error) {
        std::cerr << "Test failed: "
                  << error.what() << '\n';
        return 1;
    }

    return 0;
}