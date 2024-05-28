//#include <bpf_helpers.h>
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
#include <netdutils/UidConstants.h>
#include "bpf_helpers.h"
//#include "bpf_net_helpers.h"
//#include "netdbpf/bpf_shared.h"
//#include "netdbpf/ss_bpf_shared.h"
#include <ss_bpf_shared.h>
//APE : start
#include <linux/pkt_cls.h>
#include <linux/filter.h>

// bionic kernel uapi linux/udp.h header is munged...
#define __kernel_udphdr udphdr
#include <linux/udp.h>
//APE : end

// This is used for xt_bpf program only.
#define BPF_NOMATCH 0
#define BPF_MATCH 1

//APE : start
#define IPV6_PROTO_OFF offsetof(struct ipv6hdr, nexthdr)
#define IP_OFF_SRC   (offsetof(struct iphdr, saddr))
#define IP_OFF_DST   (offsetof(struct iphdr, daddr))
#define IP_ETH_OFF_SRC   (ETH_HLEN + IP_OFF_SRC)
#define IP_ETH_OFF_DST   (ETH_HLEN + IP_OFF_DST)

#define TCP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))
#define TCP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))

#define UDP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest))
#define UDP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, source))
// > APE:End

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_DATA_USAGE
#define DEFAULT_MTU_SIZE 1500
#define TCP_TS_SIZE 12
#define IPV4_TCP_SIZE sizeof(struct iphdr) + sizeof(struct tcphdr) + TCP_TS_SIZE
#define IPV6_TCP_SIZE sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + TCP_TS_SIZE

#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
//#endif 

DEFINE_BPF_MAP(oem_uid_owner_map, HASH, uint32_t, OemUidOwnerValue, OEM_UID_OWNER_MAP_SIZE)

// < APE:Start
#define SEMAPE_UID_DEST_MAP_SIZE 2048
DEFINE_BPF_MAP(ape_uid_dest_map, HASH, uint32_t, uint8_t, SEMAPE_UID_DEST_MAP_SIZE)
DEFINE_BPF_MAP(ape_uid_dest6_map, HASH, uint16_t, uint8_t, SEMAPE_UID_DEST_MAP_SIZE)
// > APE:End

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_DATA_USAGE
#define MBB_MAC_BYTE_MAP_SIZE 50
#define MBB_ARRAY_MAP_SIZE 10
DEFINE_BPF_MAP(mbb_mac_data_map, HASH, uint64_t, uint64_t, MBB_MAC_BYTE_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_total_map, HASH, uint32_t, uint64_t, MBB_ARRAY_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_pause_map, HASH, uint64_t, uint64_t, MBB_MAC_BYTE_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_gpause_map, HASH, uint32_t, uint64_t, MBB_ARRAY_MAP_SIZE)
//#endif

static __always_inline int is_system_uid(uint32_t uid) {
    return (uid <= MAX_SYSTEM_UID) && (uid >= MIN_SYSTEM_UID);
}

// "bpf_net_helpers.h" removed. argg! re-invent the wheel.
static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to,
                                 int len) = (void*)BPF_FUNC_skb_load_bytes;

static uint32_t (*bpf_get_socket_uid)(struct __sk_buff* skb) = (void*)BPF_FUNC_get_socket_uid;

// Android only supports little endian architectures
#define htons(x) (__builtin_constant_p(x) ? ___constant_swab16(x) : __builtin_bswap16(x))
#define htonl(x) (__builtin_constant_p(x) ? ___constant_swab32(x) : __builtin_bswap32(x))
#define ntohs(x) htons(x)
#define ntohl(x) htonl(x)

//< APE : start
static inline bool ape_is_uid_allowed(struct __sk_buff* skb){

    uint32_t sock_uid = bpf_get_socket_uid(skb);
    if (is_system_uid(sock_uid)) return BPF_MATCH;

    OemUidOwnerValue *semApeMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
    if (semApeMatch)
        return semApeMatch->rule & SEMAPE_WLAN_MATCH;

    return BPF_NOMATCH;
}

/* LO, Private IP and ZeroConfig IP to be exempted */
static int isPrivate(__u32 ip_addr) {

    return ((ip_addr & 0xFF000000) == 0x7F000000) /* 127.0.0.0/8    (loopback) */ ||
           ((ip_addr & 0xFFFF0000) == 0xC0A80000) /* 192.168.0.0/16 (private)  */ ||
           ((ip_addr & 0xFF000000) == 0x0A000000) /* 10.0.0.0/8     (private)  */ ||
           ((ip_addr & 0xFFF00000) == 0xAC100000) /* 172.16.0.0/12  (private)  */ ||
           ((ip_addr & 0xFFFF0000) == 0xA9FE0000) /* 169.254.0.0/16 (zeroconf) */;
}

static inline void ape_mark_uid_dest_map(struct __sk_buff* skb, int offset){
    __u32 key = ntohl(load_word(skb, offset));
    __u8 mark = 1;

    bpf_ape_uid_dest_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
}

static inline void ape_mark_uid_dest6_map(__u16 key){
    __u8 mark = 1;

    bpf_ape_uid_dest6_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
}

//SEC("schedcls/ingress/ape_ether")
DEFINE_BPF_PROG("schedcls/ingress/ape_ether", AID_ROOT, AID_SYSTEM, sched_cls_ingress_ape_ether)
(struct __sk_buff* skb) {

    if (skb->protocol == htons(ETH_P_IP)) {
        __u32 key = ntohl(load_word(skb, IP_ETH_OFF_SRC));
        __u8 *mark = bpf_ape_uid_dest_map_lookup_elem(&key);
        if (mark || isPrivate(ntohl(key))) {
            //skb->priority = 7;
            return TC_ACT_OK;
        }
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        int offset = ETH_HLEN + IPV6_PROTO_OFF;
        int ret = 0;
        uint8_t proto;
        ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
        if (!ret) {
            if (proto == IPPROTO_TCP) {
                __u16 key = load_half(skb, TCP6_DPORT_OFF);
                __u8 *mark = bpf_ape_uid_dest6_map_lookup_elem(&key);
                if (mark) {
                    //skb->priority = 7;
                    return TC_ACT_OK;
                }
            } else if (proto == IPPROTO_UDP) {
                __u16 key = load_half(skb, UDP6_DPORT_OFF);
                __u8 *mark = bpf_ape_uid_dest6_map_lookup_elem(&key);
                if (mark) {
                    //skb->priority = 7;
                    return TC_ACT_OK;
                }
            }
        }
    }
    skb->priority = 0;
    return TC_ACT_UNSPEC;
}

//SEC("schedcls/egress/ape_ether")
DEFINE_BPF_PROG("schedcls/egress/ape_ether", AID_ROOT, AID_SYSTEM, sched_cls_egress_ape_ether)
(struct __sk_buff* skb) {

    bool is_allowed =  ape_is_uid_allowed(skb);
    if (skb->protocol == htons(ETH_P_IP)) {
        __u32 key = load_word(skb, IP_ETH_OFF_DST);
        if (isPrivate(key)) {
            return TC_ACT_OK;
        }
    }
    
    if (is_allowed) {
        if (skb->protocol == htons(ETH_P_IP)) {
            ape_mark_uid_dest_map(skb, IP_ETH_OFF_DST);
            //skb->priority = 7;
            return TC_ACT_OK;
        } else if (skb->protocol == htons(ETH_P_IPV6)) {
            int ret = 0;
            int offset = ETH_HLEN + IPV6_PROTO_OFF;
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
            if (!ret) {
                if (proto == IPPROTO_TCP) {
                    __u16 key = load_half(skb, TCP6_SPORT_OFF);
                    ape_mark_uid_dest6_map(key);
                    //skb->priority = 7;
                    return TC_ACT_OK;
                } else if (proto == IPPROTO_UDP) {
                    __u16 key = load_half(skb, UDP6_SPORT_OFF);
                    ape_mark_uid_dest6_map(key);
                    //skb->priority = 7;
                    return TC_ACT_OK;
                }
            }
        }
    }

    //skb->priority = 0;
    return TC_ACT_UNSPEC;
}
// > APE : end

// < GMS-CORE : start
DEFINE_BPF_PROG("skfilter/mobilefw/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_mobilefw_prog)
(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    OemUidOwnerValue* firewallMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
        if (firewallMatch) {
            return firewallMatch->rule 
                & FIREWALL_MOBILE_DATA_MATCH ? BPF_MATCH : BPF_NOMATCH;
        }
    return BPF_NOMATCH;
}

DEFINE_BPF_PROG("skfilter/wlanfw/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_wlanfw_prog)
(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    OemUidOwnerValue* firewallMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
    if (firewallMatch) {
        return firewallMatch->rule 
            & FIREWALL_WLAN_MATCH ? BPF_MATCH : BPF_NOMATCH;
    }
    return BPF_NOMATCH;
}
// > GMS-CORE : end

//< QBOX : START
DEFINE_BPF_PROG("skfilter/qbox/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_qbox_prog)
(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    // for SYSTEM UID no need to lookup. Only for user range
    if (is_system_uid(sock_uid)) return BPF_NOMATCH;

    OemUidOwnerValue* qboxMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
    if (qboxMatch) return qboxMatch->rule & QBOX_MATCH;
    return BPF_NOMATCH;
}
//> QBOX : END

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_DATA_USAGE
//< S-HS : START
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
        
        if(skb->protocol == htons(ETH_P_IP)) {
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                //(void) tcph;
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
            }
            // Prevent multicast packets from being accounted.
            if (skb->pkt_type != PACKET_HOST) {
                return TC_ACT_UNSPEC;
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
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets sourced from ::1 or fe80::/64 or other weirdness.
                __be32 src32 = ip6->saddr.s6_addr32[0];
                if (src32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (src32 & htonl(0xe0000000)) != htonl(0x20000000))    // 2000::/3 Global Unicast
                   {
                       return TC_ACT_UNSPEC;
                   }
                // Prevent multicast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets destined to ::1 or fe80::/64 or other weirdness.
                __be32 dst32 = ip6->daddr.s6_addr32[0];
                if (dst32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (dst32 & htonl(0xe0000000)) != htonl(0x20000000))    // 2000::/3 Global Unicast
                   {
                       return TC_ACT_UNSPEC;
                   }
                // In the upstream direction do not forward traffic within the same /64 subnet.
                if ((src32 == dst32) && (ip6->saddr.s6_addr32[1] == ip6->daddr.s6_addr32[1]))
                   {
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
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
            }
        }
        
        // We drop any IP packet, irrespective of the protocol. 
        if(isLimitReached)     return TC_ACT_SHOT;
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
        
        if(skb->protocol == htons(ETH_P_IP)) {
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
            }
            // Prevent multicast packets from being accounted.
            if (skb->pkt_type != PACKET_HOST) {
                return TC_ACT_UNSPEC;
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
                // Prevent multicast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets sourced from ::1 or fe80::/64 or other weirdness.
                __be32 src32 = ip6->saddr.s6_addr32[0];
                if (src32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (src32 & htonl(0xe0000000)) != htonl(0x20000000))    // 2000::/3 Global Unicast
                   {
                       return TC_ACT_UNSPEC;
                   }
                // Protect against forwarding packets destined to ::1 or fe80::/64 or other weirdness.
                __be32 dst32 = ip6->daddr.s6_addr32[0];
                if (dst32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (dst32 & htonl(0xe0000000)) != htonl(0x20000000))    // 2000::/3 Global Unicast
                   {
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
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
            }
        }
        // We drop any IP packet, irrespective of the protocol. 
        if(isLimitReached)     return TC_ACT_SHOT;
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_UNSPEC;
}
// S-HS : END >
//#endif

LICENSE("Apache 2.0");
CRITICAL("netd");