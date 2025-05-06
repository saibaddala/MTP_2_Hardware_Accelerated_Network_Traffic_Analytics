#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <string>
#include <chrono>

struct PacketHeaders
{
    std::string src_ip;
    std::string dst_ip;
    int src_port;
    int dst_port;
    std::string protocol;
    int length;
    std::chrono::system_clock::time_point timestamp;
};

PacketHeaders parse_packet(const unsigned char *packet, int len, std::chrono::system_clock::time_point timestamp);

void print_packet_headers(const PacketHeaders &pkt);

#endif // PACKET_PARSER_H
