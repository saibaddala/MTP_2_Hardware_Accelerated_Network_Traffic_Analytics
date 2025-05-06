#include "feature_extraction.h"
#include <numeric>
#include <cmath>
#include <algorithm>
#include <iostream>

Features extract_features(const std::vector<std::size_t> &timestamps, const std::vector<int> &packet_sizes)
{
    Features features;
    float epsilon = 1e-6;
    float total_bytes = std::accumulate(packet_sizes.begin(), packet_sizes.end(), 0);

    // Calculate inter-arrival times (IATs)
    std::vector<float> iats;
    for (std::size_t i = 1; i < timestamps.size(); ++i)
    {
        iats.push_back(timestamps[i] - timestamps[i - 1]);
    }

    if (!iats.empty())
    {
        features.min_iat = *std::min_element(iats.begin(), iats.end());
        features.max_iat = *std::max_element(iats.begin(), iats.end());
        features.mean_iat = std::accumulate(iats.begin(), iats.end(), 0.0) / iats.size();
        features.std_iat = (iats.size() > 1)
            ? std::sqrt(std::accumulate(iats.begin(), iats.end(), 0.0,
                [mean = features.mean_iat](float sum, float iat) {
                    return sum + (iat - mean) * (iat - mean);
                }) / (iats.size() - 1))
            : 0.0;
    }
    else
    {
        features.min_iat = features.max_iat = features.mean_iat = features.std_iat = 0.0;
    }

    float duration = timestamps.back() - timestamps.front() + epsilon; // Avoid division by zero
    features.flowPktsPerSecond = timestamps.size() / duration;
    features.flowBytesPerSecond = total_bytes / duration;

    // 🔥 Added: Active and Idle Times Calculation
    const float ACTIVE_THRESHOLD = 5000.0; // 5 seconds in milliseconds (adjust if needed)
    std::vector<float> active_durations;
    std::vector<float> idle_durations;

    float active_start = timestamps.front();
    for (std::size_t i = 1; i < timestamps.size(); ++i)
    {
        float gap = timestamps[i] - timestamps[i - 1];
        if (gap > ACTIVE_THRESHOLD)
        {
            // End of an active period
            active_durations.push_back(timestamps[i - 1] - active_start);
            idle_durations.push_back(gap);
            active_start = timestamps[i];
        }
    }
    // Last active period
    active_durations.push_back(timestamps.back() - active_start);

    // Helper lambdas to calculate min, mean, max, std
    auto calculate_min = [](const std::vector<float> &v) -> float {
        return v.empty() ? 0.0 : *std::min_element(v.begin(), v.end());
    };
    auto calculate_max = [](const std::vector<float> &v) -> float {
        return v.empty() ? 0.0 : *std::max_element(v.begin(), v.end());
    };
    auto calculate_mean = [](const std::vector<float> &v) -> float {
        return v.empty() ? 0.0 : std::accumulate(v.begin(), v.end(), 0.0) / v.size();
    };
    auto calculate_std = [](const std::vector<float> &v, float mean) -> float {
        if (v.size() <= 1) return 0.0;
        return std::sqrt(std::accumulate(v.begin(), v.end(), 0.0,
            [mean](float sum, float val) { return sum + (val - mean) * (val - mean); }) / (v.size() - 1));
    };

    // Active Times
    features.min_active = calculate_min(active_durations);
    features.mean_active = calculate_mean(active_durations);
    features.max_active = calculate_max(active_durations);
    features.std_active = calculate_std(active_durations, features.mean_active);

    // Idle Times
    features.min_idle = calculate_min(idle_durations);
    features.mean_idle = calculate_mean(idle_durations);
    features.max_idle = calculate_max(idle_durations);
    features.std_idle = calculate_std(idle_durations, features.mean_idle);

    return features;
}

// 🖥️ Helper function to display features
void print_features(const Features &f)
{
    std::cout << "Extracted Features:\n";
    std::cout << "  Min IAT (ms): " << f.min_iat / 1000.0 << "\n";
    std::cout << "  Max IAT (ms): " << f.max_iat / 1000.0<< "\n";
    std::cout << "  Mean IAT (ms): " << f.mean_iat  / 1000.0 << "\n";
    std::cout << "  Std IAT (ms): " << f.std_iat  / 1000.0 << "\n";
    std::cout << "  Packets/sec: " << f.flowPktsPerSecond << "\n";
    std::cout << "  Bytes/sec: " << f.flowBytesPerSecond << "\n";
    std::cout << "  Min Active (ms): " << f.min_active / 1000.0 << "\n";
    std::cout << "  Mean Active (ms): " << f.mean_active / 1000.0 << "\n";
    std::cout << "  Max Active (ms): " << f.max_active / 1000.0 << "\n";
    std::cout << "  Std Active (ms): " << f.std_active / 1000.0 << "\n";
    std::cout << "  Min Idle (ms): " << f.min_idle / 1000.0 << "\n";
    std::cout << "  Mean Idle (ms): " << f.mean_idle / 1000.0 << "\n";
    std::cout << "  Max Idle (ms): " << f.max_idle / 1000.0 << "\n";
    std::cout << "  Std Idle (ms): " << f.std_idle / 1000.0 << "\n";
}

