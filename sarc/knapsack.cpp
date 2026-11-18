#include "knapsack.hpp"

#include <algorithm>
#include <numeric>

namespace sarc
{
    KnapsackResult knapsack_greedy(const std::vector<KnapsackItem>& items,
                                   std::uint64_t capacity)
    {
        std::vector<std::size_t> order(items.size());
        std::iota(order.begin(), order.end(), std::size_t{ 0 });

        auto ratio = [&](std::size_t i)
        {
            const double w = items[i].weight ? static_cast<double>(items[i].weight) : 1.0;
            return static_cast<double>(items[i].value) / w;
        };

        std::stable_sort(order.begin(), order.end(),
            [&](std::size_t a, std::size_t b) { return ratio(a) > ratio(b); });

        KnapsackResult result;
        std::uint64_t used = 0;

        for (std::size_t i : order)
        {
            if (items[i].weight <= capacity - used)
            {
                used += items[i].weight;
                result.value += items[i].value;
                result.chosen.push_back(i);
            }
        }

        std::sort(result.chosen.begin(), result.chosen.end());
        result.weight = used;
        return result;
    }

    KnapsackResult knapsack_dp(const std::vector<KnapsackItem>& items,
                               std::uint64_t capacity,
                               std::uint64_t max_cells)
    {
        KnapsackResult result;
        const std::uint64_t n = items.size();

        if (n == 0)
            return result;

        std::uint64_t unit = 1;

        if (n * (capacity + 1) > max_cells)
            unit = (n * (capacity + 1) + max_cells - 1) / max_cells;

        const std::uint64_t cap_units = capacity / unit;
        const std::size_t width = static_cast<std::size_t>(cap_units + 1);

        std::vector<std::uint64_t> best(width, 0);
        std::vector<bool> take(static_cast<std::size_t>(n) * width, false);
        std::vector<std::uint64_t> w_units(items.size());

        for (std::size_t i = 0; i < items.size(); ++i)
        {
            w_units[i] = (items[i].weight + unit - 1) / unit;

            if (w_units[i] > cap_units)
                continue;

            const std::size_t wi = static_cast<std::size_t>(w_units[i]);

            for (std::size_t c = width - 1; c >= wi; --c)
            {
                const std::uint64_t candidate = best[c - wi] + items[i].value;

                if (candidate > best[c])
                {
                    best[c] = candidate;
                    take[i * width + c] = true;
                }

                if (c == 0)
                    break;
            }
        }

        std::size_t c = width - 1;

        for (std::size_t i = items.size(); i-- > 0;)
        {
            if (take[i * width + c])
            {
                result.chosen.push_back(i);
                result.value += items[i].value;
                result.weight += items[i].weight;
                c -= static_cast<std::size_t>(w_units[i]);
            }
        }

        std::sort(result.chosen.begin(), result.chosen.end());
        result.unit = unit;
        return result;
    }

    KnapsackResult pack_items(const std::vector<KnapsackItem>& items,
                              std::uint64_t capacity,
                              PackerKind kind)
    {
        KnapsackResult greedy = knapsack_greedy(items, capacity);

        if (kind == PackerKind::Greedy)
            return greedy;

        KnapsackResult dp = knapsack_dp(items, capacity);
        return dp.value >= greedy.value ? dp : greedy;
    }
}
