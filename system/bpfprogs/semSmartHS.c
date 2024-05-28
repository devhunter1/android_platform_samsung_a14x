/******************************************************************************************************
 *  FILENAME: semSmartHS.c
 *
 *  DESCRIPTION :
 *        eBPF based functions to monitor and control the connected hotspot client.
 *
 *  AUTHOR : Madhan Raj Kanagarathinam
 *  DATE: 2023
 *  VERSION 1.0
 *
 *  NOTE:
 *
 *
 *  COPYRIGHT BY Samsung Electronics. ALL RIGHTS RESERVED
 ******************************************************************************************************/
#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include "bpf_helpers.h"
#include <ss_bpf_shared.h>
#include <netinet/in.h>  // Required for using htonl and htons

#include <linux/pkt_cls.h>
#include <linux/filter.h>

// bionic kernel uapi linux/udp.h header is munged...
#define __kernel_udphdr udphdr
#include <linux/udp.h>


#define IPV6_PROTO_OFF offsetof(struct ipv6hdr, nexthdr)
#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
#define TCP_DPORT_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF     (ETH_HLEN + sizeof(struct iphdr)  + offsetof(struct tcphdr, source))
#define UDP_DPORT_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_SPORT_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define TCP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))
#define TCP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))
#define UDP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest))
#define UDP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, source))

// "bpf_net_helpers.h" removed. argg! re-invent the wheel.
static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to,
                                 int len) = (void*)BPF_FUNC_skb_load_bytes;

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_DATA_USAGE
#define DEFAULT_MTU_SIZE 1500
#define TCP_TS_SIZE 12
#define IPV4_TCP_SIZE sizeof(struct iphdr) + sizeof(struct tcphdr) + TCP_TS_SIZE
#define IPV6_TCP_SIZE sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + TCP_TS_SIZE

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_DATA_USAGE
#define MBB_MAC_BYTE_MAP_SIZE 50
#define MBB_ARRAY_MAP_SIZE 10
DEFINE_BPF_MAP(mbb_mac_data_map, HASH, uint64_t, uint64_t, MBB_MAC_BYTE_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_total_map, HASH, uint32_t, uint64_t, MBB_ARRAY_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_pause_map, HASH, uint64_t, uint64_t, MBB_MAC_BYTE_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_gpause_map, HASH, uint32_t, uint64_t, MBB_ARRAY_MAP_SIZE)
//#endif

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_PRIORITIZE_TRAFFIC
DEFINE_BPF_MAP(mbb_mac_rt_map, HASH, uint64_t, uint32_t, MBB_MAC_BYTE_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_rtbyte_map, HASH, uint64_t, uint64_t, MBB_MAC_BYTE_MAP_SIZE)
/******* NSD disable -- not commenting : used for dummy update *******/
DEFINE_BPF_MAP(mbb_ipport_priority_map, HASH, PortProtStruct, uint8_t, PORTPROTSTRUCT_MAP_SIZE)
DEFINE_BPF_MAP(mbb_ipv6port_priority_map, HASH, PortProtStruct, uint8_t, PORTPROTSTRUCT_MAP_SIZE)
//#endif

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_DATA_USAGE
//< S-HS : START
/***************************************************************
* Function:  mbb_mark_mac_rt_map
* ------------------------------------
* Count the Real time packets and calculate the total size of real time
* traffic for each MAC address. This value is used in framework to detect
* real time and non-real time traffic and make decisions to enable and
* disable prioritization.

* key: MAC key in uint64_t converted format
* byte: the packet len without GRO
*****************************************************************/

// TODO: Check GRO as well? But we dont need actual bytes
static inline void mbb_mark_mac_rt_map(uint64_t key, uint64_t byte) {
    uint32_t *rtPackets = bpf_mbb_mac_rt_map_lookup_elem(&key);
    uint64_t *rtByteKey = bpf_mbb_mac_rtbyte_map_lookup_elem(&key);

    uint32_t onePacket = 1;
    if(rtPackets && rtByteKey) {
        __sync_fetch_and_add(rtPackets, onePacket);
        __sync_fetch_and_add(rtByteKey, byte);

    } else {
        bpf_mbb_mac_rt_map_update_elem(&key, &onePacket, 0);
        bpf_mbb_mac_rtbyte_map_update_elem(&key, &byte, 0);
    }
}

/***************************************************************
* Function:  size_without_gro
* ------------------------------------
* Due to Genreric Recieve Offloading (GRO) function, we can see
* multiple packets with same header to reduce per-packet processing
* overhead. However, on-the-air only the actual MTU of the packets
* are transmitted. Though, we see a higher number, we have to compute
* the data bytes with the actual header on-the-air. This function
* computes the size with actual overhead. Known problem: We add the
* the size of TCP packet even for UDP packets. Google assumes that
* offloading is not possible in UDP protocol. However, in the
* UDP-based QUIC protocol, UDP offloading is possible.
*
*
* byte: the packet len after GRO
* overhead: Determines the TCP/IP L3/L4 packet overhead on the wire
*
* returns: probable actual size before GRO
*****************************************************************/

static inline uint64_t size_without_gro(uint64_t byte, int overhead) {
    if(byte > DEFAULT_MTU_SIZE) {
        int packets = 1;
        int mss = DEFAULT_MTU_SIZE - overhead;
        uint64_t payload = byte - overhead;
        packets = (payload + mss - 1) / mss;
        byte = overhead * packets + payload;
    }
    return byte;
}

/***************************************************************
* Function:  isRtPort
* ------------------------------------
* Check if a port has real time traffic or non real time traffic.
* This function is used in the data usage filter and is used to determine
* if a packet is real time or not.
*
* port: port in unit32_t converted format
*
* returns: 1 if a port is real-time else return 0.
*****************************************************************/
static inline bool isRtPort(uint32_t port) {
    /*********************************************************************
    * Port > 1023 - Not well known ports: Avoid QUIC, DNS, and other traffic
    * Port : 5353 - mDNS (optional to skip, as we already skip Multicast protocol)
    * Port : 1900 - SSDP Discovery (optional to skip, multicast protocol)
    * Port : 1194, 4500, 2408 - IPSEC and OpenVPN UDP ports
    *********************************************************************/
    if (port > 1023 && port!= 5353 && port!=1900 && port!=4500 && port!=1194 && port!=2408)
        return 1;
    return 0;
}

/***************************************************************
* Function:  pause_or_update_datausage
* ------------------------------------
* updates the data usage of the clients, based on the MAC address.
* additionally, it also determines if the specific client has reached its allowed quota.
*
*
* key: MAC key in uint64_t converted format
* byte: the packet len to be updated
* overhead: Determines the TCP/IP L3/L4 packet overhead on the wire
*
*
* returns: if the specific client has to be paused or continue.
*****************************************************************/
static inline bool pause_or_update_datausage(uint64_t key, uint64_t byte, int overhead) {
    uint32_t globalKey = 1;
    uint64_t *pauseQuota = bpf_mbb_mac_pause_map_lookup_elem(&key);
    uint64_t *pauseGQuota = bpf_mbb_mac_gpause_map_lookup_elem(&globalKey);

    uint64_t *byteClient = bpf_mbb_mac_data_map_lookup_elem(&key);
    uint64_t *byteTotal = bpf_mbb_mac_total_map_lookup_elem(&globalKey);

    uint64_t curbyte = size_without_gro(byte, overhead);

    if(byteTotal) {
        if(pauseGQuota && (*byteTotal + curbyte) > *pauseGQuota)
            return 1;
    } else {
        if(pauseGQuota && curbyte > *pauseGQuota)
            return 1;
    }

    // If byteClient, then there is already existing stats for the MAC key
    if(byteClient) {
        // Check if the pauseQuota is set for the client and if current size can exceed the limit
        if(pauseQuota && (*byteClient + curbyte) > *pauseQuota)
            return 1;

        __sync_fetch_and_add(byteClient, curbyte);
    } else {
        // Pause even if it is first ever data packet (TCP/UDP)
        if(pauseQuota && curbyte > *pauseQuota)
            return 1;

        // first ever update of data curbyte.
        bpf_mbb_mac_data_map_update_elem(&key, &curbyte, 0);
    }

    if(byteTotal) __sync_fetch_and_add(byteTotal, curbyte);
    else bpf_mbb_mac_total_map_update_elem(&globalKey, &curbyte, 0);

    // dont pause, update completed
    return 0;

}

DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/mbb_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_ingress_mbb_swlan)
(struct __sk_buff* skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    const int l2_header_size = sizeof(struct ethhdr);

    //Not a good packet
    if (data + l2_header_size + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC; // Pipe or unspec? should we let the forward handle it ?
    }

    if(skb->protocol == htons(ETH_P_IP) || skb->protocol == htons(ETH_P_IPV6)) {
        struct ethhdr *eth  = data;

        int ret = 0;
        uint64_t byte = skb->len;
        bool isLimitReached = 0; // To check if the specific client has reached the limit
        bool is_rt_udp = 0;
        bool is_ipv4 = 0;
        uint16_t dport = 0;

        if(skb->protocol == htons(ETH_P_IP)) {
            is_ipv4 = 1;
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                //(void) tcph;
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;

                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
            }
        } else {
            // Just to keep the loader happy
            if(skb->protocol == htons(ETH_P_IPV6)) {
                struct ipv6hdr* ip6 = (void*)(eth + 1);
                if (eth->h_proto != htons(ETH_P_IPV6)) return TC_ACT_UNSPEC;
                if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_UNSPEC;
                if (ip6->version != 6) return TC_ACT_UNSPEC;
                if (ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr* tcph = (void*)(ip6 + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                    if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                }
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets sourced from ::1 or fe80::/64 or other weirdness.
                __be32 src32 = ip6->saddr.s6_addr32[0];
                if (src32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (src32 & htonl(0xe0000000)) != htonl(0x20000000)) {   // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets destined to ::1 or fe80::/64 or other weirdness.
                __be32 dst32 = ip6->daddr.s6_addr32[0];
                if (dst32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (dst32 & htonl(0xe0000000)) != htonl(0x20000000)) {    // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
                // In the upstream direction do not forward traffic within the same /64 subnet.
                if ((src32 == dst32) && (ip6->saddr.s6_addr32[1] == ip6->daddr.s6_addr32[1])) {
                       return TC_ACT_UNSPEC;
                }
            }
        }

        __u32 macpart1 = eth->h_source[5] | (eth->h_source[4] << 8) | (eth->h_source[3] << 16) | (eth->h_source[2] << 24);
        __u32 macpart2 = eth->h_source[1] | (eth->h_source[0] << 8);
        uint64_t key = ((uint64_t)macpart2)<<32 | macpart1;

        if(skb->protocol == htons(ETH_P_IP)) {
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, ETH_HLEN + IP_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                if(pause_or_update_datausage(key, byte, IPV4_TCP_SIZE))
                    isLimitReached = 1;
                else {
                    dport = load_half(skb, UDP_DPORT_OFF);
                    if (isRtPort(dport)) {
                        is_rt_udp = 1;
                    }
                }
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV4_TCP_SIZE))
                    isLimitReached = 1;
            }
        } else {
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, ETH_HLEN + IPV6_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
                else {
                    dport = load_half(skb, UDP6_DPORT_OFF);
                    if (isRtPort(dport)) {
                        is_rt_udp = 1;
                    }
                }
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
            }
        }

        // We drop any IP packet, irrespective of the protocol.
        if(isLimitReached) {
            return TC_ACT_SHOT;
        } else {
            if(is_rt_udp) {
                int overhead = IPV6_TCP_SIZE;
                if (is_ipv4) {
                    overhead = IPV4_TCP_SIZE;
                }
                // calculate the size of the real time packet and pass it to mbb_mark_mac_rt_map
                // for adding the current packet length to total size and update the RT packet count
                uint64_t curbyte = size_without_gro(byte, overhead);
                mbb_mark_mac_rt_map(key, curbyte);
            }
        }
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_UNSPEC;
}


DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/mbb_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_egress_mbb_swlan)
(struct __sk_buff* skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    const int l2_header_size = sizeof(struct ethhdr);

    if (data + l2_header_size + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }

    if(skb->protocol == htons(ETH_P_IP) || skb->protocol == htons(ETH_P_IPV6)) {
        struct ethhdr  *eth  = data;
        int ret = 0;
        uint64_t byte = skb->len;
        bool isLimitReached = 0; // To check if the specific client has reached the limit
        bool is_rt_udp = 0;
        uint16_t sport = 0;
        bool is_ipv4 = 0;

        if(skb->protocol == htons(ETH_P_IP)) {
            is_ipv4 = 1;
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
            }
        } else {
            // Just to keep the loader happy
            if(skb->protocol == htons(ETH_P_IPV6)) {
                struct ipv6hdr* ip6 = (void*)(eth + 1);
                if (eth->h_proto != htons(ETH_P_IPV6)) return TC_ACT_UNSPEC;
                if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_UNSPEC;
                if (ip6->version != 6) return TC_ACT_UNSPEC;
                if (ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr* tcph = (void*)(ip6 + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                    if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                }
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets sourced from ::1 or fe80::/64 or other weirdness.
                __be32 src32 = ip6->saddr.s6_addr32[0];
                if (src32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (src32 & htonl(0xe0000000)) != htonl(0x20000000)) {   // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets destined to ::1 or fe80::/64 or other weirdness.
                __be32 dst32 = ip6->daddr.s6_addr32[0];
                if (dst32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (dst32 & htonl(0xe0000000)) != htonl(0x20000000)) {    // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
            }
        }

        __u32 macpart1 = eth->h_dest[5] | (eth->h_dest[4] << 8) | (eth->h_dest[3] << 16) | (eth->h_dest[2] << 24);
        __u32 macpart2 = eth->h_dest[1] | (eth->h_dest[0] << 8);
        uint64_t key = (((uint64_t)macpart2)<<32) | macpart1;

        if(skb->protocol == htons(ETH_P_IP)) {
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, ETH_HLEN + IP_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                if(pause_or_update_datausage(key, byte, IPV4_TCP_SIZE))
                    isLimitReached = 1;
                else {
                    sport = load_half(skb, UDP_SPORT_OFF);
                    if (isRtPort(sport)) {
                        is_rt_udp = 1;
                    }
                }
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV4_TCP_SIZE))
                    isLimitReached = 1;
            }
        } else {
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, ETH_HLEN + IPV6_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
                else {
                    sport = load_half(skb, UDP6_SPORT_OFF);
                        if (isRtPort(sport)) {
                            is_rt_udp = 1;
                        }
                }
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
            }
        }
        // We drop any IP packet, irrespective of the protocol.
        if(isLimitReached) {
            return TC_ACT_SHOT;
        } else {
            if(is_rt_udp) {
                int overhead = IPV6_TCP_SIZE;
                if (is_ipv4) {
                    overhead = IPV4_TCP_SIZE;
                }
                // calculate the size of the real time packet and pass it to mbb_mark_mac_rt_map
                // for adding the current packet length to total size and update the RT packet count
                uint64_t curbyte = size_without_gro(byte, overhead);
                mbb_mark_mac_rt_map(key, curbyte);
            }
        }
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_UNSPEC;
}


//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_PRIORITIZE_TRAFFIC
/****************************************************
  BPF program to check the packets in egress if they
  are real time or non real-time.
  We use the same RT port check to decide RT or NRT
*****************************************************/
DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/mbb_prio_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_egress_mbb_prio_swlan)
(struct __sk_buff* skb) {
       void *data = (void *)(long)skb->data;
       void *data_end = (void *)(long)skb->data_end;

       if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
           return TC_ACT_UNSPEC;
       }

/**** eBPF-Based Priority *******/
    int ret = 0;

    if(skb->protocol == htons(ETH_P_IP)) {
        uint8_t proto;
        int offset = ETH_HLEN + IP_PROTO_OFF;
        ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
        if(!ret && proto == IPPROTO_UDP){
            uint16_t sport = load_half(skb, UDP_SPORT_OFF);
            if (isRtPort(sport)) {
                __u8 mark = 1;
                PortProtStruct key = {(uint32_t)sport,(uint32_t)proto};
                bpf_mbb_ipport_priority_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
                return TC_ACT_OK;
            }
        }
    } else if(skb->protocol == htons(ETH_P_IPV6)){
        uint8_t proto;
        int offset = ETH_HLEN + IPV6_PROTO_OFF;
        ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
        if(!ret && proto == IPPROTO_UDP){
            uint16_t sport = load_half(skb, UDP6_SPORT_OFF);
            if (isRtPort(sport)) {
                __u8 mark = 0;
                PortProtStruct key = {(uint32_t)sport,(uint32_t)proto};
                bpf_mbb_ipport_priority_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
                return TC_ACT_OK;
            }
        }
    }
/**** eBPF-Based Priority End *******/

    return TC_ACT_UNSPEC;
}


/****************************************************
  BPF program to check the packets in ingress if they
  are real time or non real-time.
  We use the same RT port check to decide RT or NRT
*****************************************************/
DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/mbb_prio_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_ingress_mbb_prio_swlan)
(struct __sk_buff* skb) {
     void *data = (void *)(long)skb->data;
     void *data_end = (void *)(long)skb->data_end;
     if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
         return TC_ACT_UNSPEC;
     }

/**** eBPF-Based Priority Start *******/
    int ret = 0;

    if(skb->protocol == htons(ETH_P_IP)) {
        uint8_t proto;
        int offset = ETH_HLEN + IP_PROTO_OFF;
        ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
        if(!ret && proto == IPPROTO_UDP){
            uint16_t dport = load_half(skb, UDP_DPORT_OFF);
            if (isRtPort(dport)) {
                __u8 mark = 1;
                PortProtStruct key = {(uint32_t)dport,(uint32_t)proto};
                bpf_mbb_ipport_priority_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
                return TC_ACT_OK;
            }
        }
    } else if(skb->protocol == htons(ETH_P_IPV6)){
        uint8_t proto;
        int offset = ETH_HLEN + IPV6_PROTO_OFF;
        ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
        if(!ret && proto == IPPROTO_UDP){
            uint16_t dport = load_half(skb, UDP6_DPORT_OFF);
            if (isRtPort(dport)) {
                __u8 mark = 0;
                PortProtStruct key = {(uint32_t)dport,(uint32_t)proto};
                bpf_mbb_ipport_priority_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
                return TC_ACT_OK;
            }
        }
    }
/**** eBPF-Based Priority Stop *******/

    return TC_ACT_UNSPEC;

}


// S-HS : END >
//#endif

LICENSE("Apache 2.0");
CRITICAL("Sem eBPF Smart Hotspot");