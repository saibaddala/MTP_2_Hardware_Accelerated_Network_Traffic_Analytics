#ifndef FEATURE_EXTRACTION_H
#define FEATURE_EXTRACTION_H

#include <vector>

struct Features
{
    // Existing flow features
    float min_iat;
    float max_iat;
    float mean_iat;
    float std_iat;
    float flowPktsPerSecond;
    float flowBytesPerSecond;

    // 🔥 New Active Time features
    float min_active;
    float mean_active;
    float max_active;
    float std_active;

    // 🔥 New Idle Time features
    float min_idle;
    float mean_idle;
    float max_idle;
    float std_idle;
};

// Feature extraction function
Features extract_features(const std::vector<std::size_t> &timestamps, const std::vector<int> &packet_sizes);

// 🆕 Add this line to enable printing features from any file
void print_features(const Features &f);

#endif // FEATURE_EXTRACTION_H

