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

        const std::string data_a =
            "This is the confidential content of File A.";
        const std::string data_b =
            "This is different confidential content for File B.";

        manager.store_file_with_candidates("file-A", data_a);
        manager.store_file_with_candidates("file-B", data_b);

        if (manager.retrieve_file("file-A") != data_a) {
            throw std::runtime_error("File A content mismatch");
        }

        if (manager.retrieve_file("file-B") != data_b) {
            throw std::runtime_error("File B content mismatch");
        }

        std::cout << "File A storage and retrieval passed!\n";
        std::cout << "File B storage and retrieval passed!\n";
        std::cout << "Both files retained their original contents!\n";
        std::cout << "Free blocks remaining: "
                  << store.free_count() << '\n';

    } catch (const std::exception& error) {
        std::cerr << "Test failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
