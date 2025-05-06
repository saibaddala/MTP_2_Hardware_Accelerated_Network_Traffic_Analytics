#include "flow.h"
#include "feature_extraction.h"  // ⬅️ Needed for print_features
#include <numeric>
#include <cmath>
#include <iostream>  // ⬅️ Needed for std::cout

FlowManager::FlowManager() {}

// Generate a unique key based on src/dst IP, ports, and protocol
std::string FlowManager::createFlowKey(const PacketHeaders &packet)
{
    return packet.src_ip + "-" + packet.dst_ip + "-" + std::to_string(packet.src_port) + "-" +
           std::to_string(packet.dst_port) + "-" + packet.protocol;
}

// Add packet to the appropriate flow based on its key
void FlowManager::addPacket(const PacketHeaders &packet)
{
    std::string flowKey = createFlowKey(packet);
    std::size_t timestamp = std::chrono::duration_cast<std::chrono::microseconds>(packet.timestamp.time_since_epoch()).count();
    int packet_size = packet.length;

    flows[flowKey].timestamps.push_back(timestamp);
    flows[flowKey].packet_sizes.push_back(packet_size);
}

// Extract and print features for each flow
std::map<std::string, Features> FlowManager::extractFeatures()
{
    std::map<std::string, Features> raw_features;

    for (const auto &[flow_key, flow] : flows)
    {
        if (flow.timestamps.size() < 2)
            {
                std::cout << "[!] Skipping flow " << flow_key << " because it has <2 packets\n";
                continue;
            }
          
        Features features = extract_features(flow.timestamps, flow.packet_sizes);
        raw_features[flow_key] = features;

        std::cout << "\nFlow Key: " << flow_key << std::endl;
        print_features(features);  // ⬅️ Show feature values clearly
    }

    return raw_features;
}

// Retrieve all active flows
std::map<std::string, Flow> FlowManager::getFlows()
{
    return flows;
}

// Clear flow data (for next batch if needed)
void FlowManager::clearFlows()
{
    flows.clear();
}

