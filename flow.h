#ifndef FLOW_H
#define FLOW_H

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include "packet_parser.h"
#include "feature_extraction.h"

// Define structure for flow information
struct Flow
{
    std::vector<std::size_t> timestamps;
    std::vector<int> packet_sizes;
};

// Flow manager class to handle flow operations
class FlowManager
{
public:
    FlowManager();
    void addPacket(const PacketHeaders &packet);
    std::map<std::string, Flow> getFlows();
    void clearFlows();
    std::map<std::string, Features> extractFeatures();
    std::map<std::string, Features> getAllFlowFeatures();

private:
    std::map<std::string, Flow> flows;
    std::map<std::string, Features> features;
    std::string createFlowKey(const PacketHeaders &packet);
};

#endif // FLOW_H
