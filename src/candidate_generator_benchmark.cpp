
#include "storage/candidate_generator.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>
#include <numeric>

int main()
{
    crypto::Key256 key{};

    for (std::size_t i = 0; i < key.size(); ++i)
    {
        key[i] = static_cast<unsigned char>(i);
    }

    storage::CandidateGenerator generator(key);

    const std::size_t capacities[] = {1000, 10000, 100000};
    constexpr std::size_t candidate_count = 100;
    constexpr int warmup_trials = 5;
    constexpr int measured_trials = 30;

    for (const auto capacity : capacities)
    {
        // Warm-up: these measurements are discarded.
        for (int trial = 0; trial < warmup_trials; ++trial)
        {
            const auto candidates = generator.generate(
                "warmup-" + std::to_string(trial),
                capacity,
                candidate_count);

            if (candidates.size() != candidate_count)
            {
                throw std::runtime_error(
                    "Unexpected candidate count during warm-up");
            }
        }

        std::vector<double> times_ms;
        times_ms.reserve(measured_trials);

        for (int trial = 0; trial < measured_trials; ++trial)
        {
            const auto start = std::chrono::steady_clock::now();

            const auto candidates = generator.generate(
                "benchmark-file-" + std::to_string(trial),
                capacity,
                candidate_count);

            const auto end = std::chrono::steady_clock::now();

            if (candidates.size() != candidate_count)
            {
                throw std::runtime_error("Unexpected candidate count");
            }

            std::unordered_set<std::size_t> unique(
                candidates.begin(), candidates.end());

            if (unique.size() != candidate_count)
            {
                throw std::runtime_error(
                    "Duplicate candidate index detected");
            }

            for (const auto index : candidates)
            {
                if (index >= capacity)
                {
                    throw std::runtime_error(
                        "Candidate index exceeds capacity");
                }
            }

            times_ms.push_back(
                std::chrono::duration<double, std::milli>(
                    end - start)
                    .count());
        }

        const double total_ms =
            std::accumulate(times_ms.begin(), times_ms.end(), 0.0);

        const auto [min_it, max_it] = std::minmax_element(
            times_ms.begin(), times_ms.end());

        std::cout << "Capacity: " << capacity << '\n';
        std::cout << "Candidates per trial: "
                  << candidate_count << '\n';
        std::cout << "Warm-up trials: " << warmup_trials << '\n';
        std::cout << "Measured trials: " << measured_trials << '\n';
        std::cout << "Average time: "
                  << total_ms / measured_trials << " ms\n";
        std::cout << "Minimum time: " << *min_it << " ms\n";
        std::cout << "Maximum time: " << *max_it << " ms\n";
        std::cout << "Uniqueness and bounds: passed\n\n";
    }

    return 0;
}
