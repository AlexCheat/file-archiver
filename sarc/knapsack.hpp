#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace sarc
{
    enum class PackerKind
    {
        Knapsack,  // exact 0/1 DP (never worse than greedy)
        Greedy     // sort by value / weight
    };

    struct KnapsackItem
    {
        std::uint64_t weight = 0;
        std::uint64_t value = 0;
    };

    struct KnapsackResult
    {
        std::vector<std::size_t> chosen;   // ascending item indices
        std::uint64_t value = 0;
        std::uint64_t weight = 0;
        std::uint64_t unit = 1;            // weight granularity used by the DP
    };

    // Greedy by value/weight ratio; items that do not fit are skipped.
    KnapsackResult knapsack_greedy(const std::vector<KnapsackItem>& items,
                                   std::uint64_t capacity);

    // 0/1 knapsack, O(n * W). Exact when unit == 1. When n * W would exceed
    // max_cells the weights are rounded UP to a coarser unit (still feasible,
    // possibly slightly suboptimal).
    KnapsackResult knapsack_dp(const std::vector<KnapsackItem>& items,
                               std::uint64_t capacity,
                               std::uint64_t max_cells = (1ull << 26));

    // Dispatcher used by the writer. Knapsack mode returns the better of the
    // DP and greedy solutions, so it is never worse than greedy.
    KnapsackResult pack_items(const std::vector<KnapsackItem>& items,
                              std::uint64_t capacity,
                              PackerKind kind);
}
