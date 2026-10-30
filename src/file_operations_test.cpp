#include "storage/file_manager.h"

#include <iostream>
#include <stdexcept>
#include <string>

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

        const std::string original =
            "Original confidential content for update testing.";
        const std::string updated =
            "Updated confidential content.";
        const std::string other =
            "A separate file that must remain unchanged.";

        manager.store_file_with_candidates("file-A", original);
        manager.store_file_with_candidates("file-B", other);

        manager.update_file("file-A", updated);

        if (manager.retrieve_file("file-A") != updated) {
            throw std::runtime_error("Updated content mismatch");
        }

        if (manager.retrieve_file("file-B") != other) {
            throw std::runtime_error("File B changed unexpectedly");
        }

        std::cout << "File update test passed!\n";
        std::cout << "Other file integrity test passed!\n";

        manager.delete_file("file-A");

        if (store.free_count() != 97) {
            throw std::runtime_error("Unexpected free-block count after deletion");
        }

        bool missing_file_detected = false;
        try {
            manager.retrieve_file("file-A");
        } catch (const std::runtime_error&) {
            missing_file_detected = true;
        }

        if (!missing_file_detected) {
            throw std::runtime_error("Deleted file was still retrievable");
        }

        if (manager.retrieve_file("file-B") != other) {
            throw std::runtime_error("File B changed after deleting File A");
        }

        std::cout << "File deletion test passed!\n";
        std::cout << "Deleted file is no longer retrievable!\n";
        std::cout << "Remaining file integrity test passed!\n";
        std::cout << "Free blocks remaining: "
                  << store.free_count() << '\n';

    } catch (const std::exception& error) {
        std::cerr << "Test failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
