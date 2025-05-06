#include "packet_parser.h"
#include "flow.h"
#include <iostream>
#include <netinet/ip.h>   // For IPv4 headers
#include <netinet/ip6.h>  // For IPv6 headers
#include <netinet/tcp.h>  // For TCP headers
#include <netinet/udp.h>  // For UDP headers
#include <arpa/inet.h>
#include <chrono>

PacketHeaders parse_packet(const unsigned char *packet, int len, std::chrono::system_clock::time_point timestamp)
{
    std::cout << "[DEBUG] First byte: " << std::hex << (int)packet[0] << std::dec << std::endl;
    std::cout << "[DEBUG] Packet length: " << len << std::endl;

    uint8_t version = packet[0] >> 4;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string src_ip, dst_ip, protocol;

    if (version == 4)
{
    struct iphdr *ip_hdr = (struct iphdr *)(packet);

    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_hdr->saddr;
    dst_addr.s_addr = ip_hdr->daddr;

    src_ip = std::string(inet_ntoa(src_addr));
    dst_ip = std::string(inet_ntoa(dst_addr));

    // Default to TCP unless changed
    protocol = "TCP";

    int ip_header_len = ip_hdr->ihl * 4;

    if (ip_hdr->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ip_header_len);
        src_port = ntohs(tcp_hdr->source);
        dst_port = ntohs(tcp_hdr->dest);
    }
    else if (ip_hdr->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp_hdr = (struct udphdr *)(packet + ip_header_len);
        src_port = ntohs(udp_hdr->source);
        dst_port = ntohs(udp_hdr->dest);
        protocol = "UDP";
    }
    else if (ip_hdr->protocol == IPPROTO_ICMP)
    {
        protocol = "ICMP";
    }
    else
    {
        return PacketHeaders{};  // Skip other protocols
    }
}
    else if (version == 6)
    {
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet);
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst, INET6_ADDRSTRLEN);

        src_ip = std::string(src);
        dst_ip = std::string(dst);
        protocol = "TCP";

        if (ip6_hdr->ip6_nxt == IPPROTO_TCP)
        {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip6_hdr));
            src_port = ntohs(tcp_hdr->th_sport);
            dst_port = ntohs(tcp_hdr->th_dport);
        }
        else if (ip6_hdr->ip6_nxt == IPPROTO_UDP)
        {
            struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ip6_hdr));
            src_port = ntohs(udp_hdr->uh_sport);
            dst_port = ntohs(udp_hdr->uh_dport);
            protocol = "UDP";
        }
        else
        {
            return PacketHeaders{};
        }
    }
    else
    {
        std::cerr << "Unknown IP version" << std::endl;
        return PacketHeaders{};
    }

    return PacketHeaders{src_ip, dst_ip, src_port, dst_port, protocol, len, timestamp};
}

// 🖨️ Optional: Debug print for parsed headers
void print_packet_headers(const PacketHeaders &pkt)
{
    std::cout << "Packet Info:\n";
    std::cout << "  Source IP: " << pkt.src_ip << "\n";
    std::cout << "  Dest IP:   " << pkt.dst_ip << "\n";
    std::cout << "  Src Port:  " << pkt.src_port << "\n";
    std::cout << "  Dst Port:  " << pkt.dst_port << "\n";
    std::cout << "  Protocol:  " << pkt.protocol << "\n";
    std::cout << "  Length:    " << pkt.length << " bytes\n";
}

