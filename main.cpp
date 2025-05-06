#include <iostream>
#include <thread>
#include <chrono>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "packet_parser.h"
#include "flow.h"
#include "feature_extraction.h"  // for print_features()
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <atomic>

const int PROFILING_INTERVAL = 10;
const int WINDOW_DURATION = 2;

std::atomic<int> packet_count(0);
std::vector<PacketHeaders> packets;
std::chrono::steady_clock::time_point last_profiling_time = std::chrono::steady_clock::now();

// Get packet timestamp
std::chrono::system_clock::time_point get_timestamp(struct nfq_data *nfa)
{
    struct timeval timestamp;
    if (nfq_get_timestamp(nfa, &timestamp) == 0)
    {
        return std::chrono::system_clock::from_time_t(timestamp.tv_sec) +
               std::chrono::microseconds(timestamp.tv_usec);
    }
    else
    {
        return std::chrono::system_clock::now();  // fallback
    }
}

// Group packets into flows
FlowManager split_into_flows()
{
    FlowManager flowManager;
    for (const auto &packet : packets)
    {
        flowManager.addPacket(packet);
    }
    packets.clear();
    return flowManager;
}

int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
    {
        uint32_t id = ntohl(ph->packet_id);
        unsigned char *packet;
        int packet_len = nfq_get_payload(nfa, &packet);

        if (packet_len >= 0)
        {
            auto timestamp = get_timestamp(nfa);
            
            PacketHeaders packet_headers = parse_packet(packet, packet_len, timestamp);
            print_packet_headers(packet_headers);  
            packets.push_back(packet_headers);
            packet_count++;

            // If enough time has passed, extract features
            if (!packets.empty())
            {
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                                    packet_headers.timestamp - packets.front().timestamp)
                                    .count();

                if (duration >= WINDOW_DURATION)
                {
                    FlowManager flowManager = split_into_flows();
                    auto flow_map = flowManager.getFlows();
                    for (const auto &[key, flow] : flow_map)
                    {
                        std::cout << "Flow [" << key << "] has " << flow.timestamps.size() << " packets.\n";
                    }

                    std::map<std::string, Features> flowFeatures = flowManager.extractFeatures();

                    // ✅ Print features
                    for (const auto &[flow_key, features] : flowFeatures)
                    {
                        std::cout << "\nFlow Key: " << flow_key << std::endl;
                        print_features(features);
                    }

                    std::cout << "=====================" << std::endl;
                }
            }

            // Log packet rate
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_profiling_time).count() >= PROFILING_INTERVAL)
            {
                std::cout << "Processed " << packet_count << " packets in the last " << PROFILING_INTERVAL << " seconds.\n";
                last_profiling_time = now;
                packet_count = 0;
            }
        }

        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    return 0;
}

void start_packet_processing(int queue_num)
{
    struct nfq_handle *handle = nfq_open();
    if (!handle)
    {
        std::cerr << "Error opening NFQ\n";
        return;
    }

    nfq_unbind_pf(handle, AF_INET);
    nfq_bind_pf(handle, AF_INET);

    struct nfq_q_handle *qh = nfq_create_queue(handle, queue_num, &process_packet, nullptr);
    if (!qh)
    {
        std::cerr << "Error creating NFQ queue\n";
        return;
    }

    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    int fd = nfq_fd(handle);
    char buf[4096];

    while (true)
    {
        int rv = recv(fd, buf, sizeof(buf), 0);
        nfq_handle_packet(handle, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_unbind_pf(handle, AF_INET);
    nfq_close(handle);
}

int main()
{
    int queue_num = 1;
    std::cout << "🚀 Starting Packet Parsing + Feature Extraction...\n";
    std::thread processing_thread(start_packet_processing, queue_num);
    processing_thread.join();
    return 0;
}

