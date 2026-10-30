
#include "storage/candidate_generator.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

int main()
{
    try
    {
        crypto::Key256 key{};

        for (std::size_t i = 0; i < key.size(); ++i)
        {
            key[i] = static_cast<unsigned char>(i);
        }

        storage::CandidateGenerator generator(key);

        const auto first = generator.generate("file-A", 100, 25);
        const auto second = generator.generate("file-A", 100, 25);
        const auto other = generator.generate("file-B", 100, 25);

        if (first != second)
        {
            throw std::runtime_error(
                "Same file ID produced different sequences");
        }

        if (first == other)
        {
            throw std::runtime_error(
                "Different file IDs produced identical sequences");
        }

        auto sorted = first;
        std::sort(sorted.begin(), sorted.end());

        if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end())
        {
            throw std::runtime_error("Duplicate candidate indices found");
        }

        for (const auto index : first)
        {
            if (index >= 100)
            {
                throw std::runtime_error("Candidate index is out of range");
            }
        }

        std::cout << "Determinism test passed!\n";
        std::cout << "Distinct indices test passed!\n";
        std::cout << "Bounds test passed!\n";
        std::cout << "Different file IDs test passed!\n";
    }
    catch (const std::exception &error)
    {
        std::cerr << "Test failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
