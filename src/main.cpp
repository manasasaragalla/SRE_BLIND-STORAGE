
#include "crypto/crypto_utils.h"
#include "storage/file_manager.h"

#include <iostream>
#include <stdexcept>
#include <string>

int main()
{
    try
    {
        // -------------------------------------------------
        // TEST 1: Original file update demonstration
        // -------------------------------------------------
        {
            storage::BlockStore store(30);
            const auto key = crypto::generate_key();
            storage::FileManager manager(store, key);

            manager.store_file("file_001", "Original file contents.");

            const std::string updated =
                "Updated confidential file contents.";

            manager.update_file("file_001", updated);

            const std::string recovered =
                manager.retrieve_file("file_001");

            if (recovered != updated)
            {
                throw std::runtime_error(
                    "Updated content mismatch");
            }

            std::cout << "=== Original File Update Test ===\n";
            std::cout << "File update passed!\n";
            std::cout << "Updated content retrieval passed!\n";
            std::cout << "Updated block version: "
                      << store.get(0).version << '\n';
            std::cout << "Recovered: " << recovered << '\n';
            std::cout << "Free blocks remaining: "
                      << store.free_count() << "\n\n";
        }

        // -------------------------------------------------
        // TEST 2: Candidate-based storage and retrieval
        // -------------------------------------------------
        {
            crypto::Key256 encryption_key{};
            crypto::Key256 id_key{};

            for (std::size_t i = 0; i < 32; ++i)
            {
                encryption_key[i] =
                    static_cast<unsigned char>(i + 1);
                id_key[i] =
                    static_cast<unsigned char>(100 + i);
            }

            storage::BlockStore store(100);
            storage::FileManager manager(
                store, encryption_key, id_key);

            const std::string data_a =
                "Confidential content stored using candidates.";
            const std::string data_b =
                "A separate confidential file.";

            manager.store_file_with_candidates("file-A", data_a);
            manager.store_file_with_candidates("file-B", data_b);

            if (manager.retrieve_file("file-A") != data_a)
            {
                throw std::runtime_error(
                    "Candidate retrieval failed for File A");
            }

            if (manager.retrieve_file("file-B") != data_b)
            {
                throw std::runtime_error(
                    "Candidate retrieval failed for File B");
            }

            std::cout << "=== Candidate Storage Test ===\n";
            std::cout << "Candidate-based storage passed!\n";
            std::cout << "File A retrieval passed!\n";
            std::cout << "File B retrieval passed!\n";
            std::cout << "Multiple-file isolation passed!\n";
            std::cout << "Free blocks remaining: "
                      << store.free_count() << '\n';
        }

        std::cout << "\nAll main demo tests passed!\n";
    }
    catch (const std::exception &error)
    {
        std::cerr << "Test failed: "
                  << error.what() << '\n';
        return 1;
    }

    return 0;
}
