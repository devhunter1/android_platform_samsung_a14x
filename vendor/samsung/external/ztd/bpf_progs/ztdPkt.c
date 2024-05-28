#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>
#include <linux/tcp.h>

#include <stdbool.h>
#include <stdint.h>
#include <netdutils/UidConstants.h>
#include <netinet/in.h>

#include <ss_bpf_shared.h>

#include "bpf_shared.h"
#include <ztd_pkt_shared.h>

#define DEBUG 0
#define DEBUG_ENTRY (DEBUG && 0)

#if DEBUG
#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

#define USE_RINGBUF 1

#define TLS_OFFSET                  0x40
#define TLS_HELLO_MESSAGE_OFFSET    0x42

#define TLS_HELLO_MESSAGE           0x16
#define TLS_CLIENT_HELLO            0x01
#define TLS_SERVER_HELLO            0x02

#define BYTES_PER_SEGMENT    4

#define MAX_PKT_SEGMENTS     HELLO_DATA_LEN/BYTES_PER_SEGMENT
#define PKT_SEGMENT_SIZE_128 (1 << 7)
#define PKT_SEGMENT_SIZE_64  (1 << 6)
#define PKT_SEGMENT_SIZE_32  (1 << 5)
#define PKT_SEGMENT_SIZE_16  (1 << 4)
#define PKT_SEGMENT_SIZE_8   (1 << 3)
#define PKT_SEGMENT_SIZE_4   (1 << 2)
#define PKT_SEGMENT_SIZE_3   3
#define PKT_SEGMENT_SIZE_2   2
#define PKT_SEGMENT_SIZE_1   1

#define IPV6_PROTO_OFF offsetof(struct ipv6hdr, nexthdr)
#define IPV6_SADDR_OFF offsetof(struct ipv6hdr, saddr)
#define IPV6_DADDR_OFF offsetof(struct ipv6hdr, daddr)

#define IP_OFF_SRC   (offsetof(struct iphdr, saddr))
#define IP_OFF_DST   (offsetof(struct iphdr, daddr))
#define IP_ETH_OFF_SRC   (ETH_HLEN + IP_OFF_SRC)
#define IP_ETH_OFF_DST   (ETH_HLEN + IP_OFF_DST)

#define TCP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))
#define TCP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))

#define TCP4_DPORT_OFF    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP4_SPORT_OFF    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))

struct tlshdr {
    uint8_t padding[2];
    uint8_t type;
    uint16_t version;
    uint16_t length;
    uint8_t hello;
};

#define DEFAULT_MTU_SIZE 1500
#define TCP_TS_SIZE 12
#define IPV4_TCP_SIZE sizeof(struct iphdr) + sizeof(struct tcphdr) + TCP_TS_SIZE
#define IPV6_TCP_SIZE sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + TCP_TS_SIZE

#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
//https://code.sec.samsung.net/codegrok/server/1716/preview/TIGER/Cinnamon/system/bpfprogs/ss_netd.c
//https://code.sec.samsung.net/codegrok/server/1716/preview/PROD_TIGER/ONEUI_5_0/ONEUI_5_0_FOLDABLE_TABLET_MR202210/Combination/QSSI/android/packages/modules/Connectivity/bpf_progs/offload.c

static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to, int len) = (void*)BPF_FUNC_skb_load_bytes;
static uint32_t(*bpf_get_socket_uid)(struct __sk_buff* skb) = (void*)BPF_FUNC_get_socket_uid;

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(tls_pkt_ringbuf, tls_pkt_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", false,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, false, false, false);
DEFINE_BPF_MAP_GRW(tls_pkt_map, PERCPU_ARRAY, uint32_t, tls_pkt_t, 1, AID_SYSTEM);
#endif

static inline __always_inline int check_tls_hello_packet(struct __sk_buff* skb, uint8_t pkt_flow) {

    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    const int l2_header_size = sizeof(struct ethhdr);

    //Not a good packet
    if (data + l2_header_size + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC; // Pipe or unspec? should we let the forward handle it ?
    }

    if (skb->protocol == htons(ETH_P_IP) || skb->protocol == htons(ETH_P_IPV6)) {
        int ret = 0;
        struct ethhdr* eth = data;
        if (skb->protocol == htons(ETH_P_IP)) {
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                //(void) tcph;
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                // TCP 3-way handshake packets.
                if (tcph->syn || tcph->fin || tcph->rst) {
                    return TC_ACT_UNSPEC;
                }
            }
        }
        else {
            // Just to keep the loader happy
            if (skb->protocol == htons(ETH_P_IPV6)) {
                struct ipv6hdr* ip6 = (void*)(eth + 1);
                if (eth->h_proto != htons(ETH_P_IPV6)) return TC_ACT_UNSPEC;
                if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_UNSPEC;
                if (ip6->version != 6) return TC_ACT_UNSPEC;
                if (ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr* tcph = (void*)(ip6 + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                    if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                }
            }
        }

        if (skb->protocol == htons(ETH_P_IP)) {
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, ETH_HLEN + IP_PROTO_OFF, &proto, 1);
            if (!ret && proto != IPPROTO_TCP) return TC_ACT_UNSPEC;

            struct tlshdr tls_header;
            ret = bpf_skb_load_bytes(skb, TLS_OFFSET, &tls_header, sizeof(struct tlshdr));
            if (tls_header.type != TLS_HELLO_MESSAGE) return TC_ACT_UNSPEC;

#if USE_RINGBUF
            uint32_t zero = 0;
            tls_pkt_t* output = bpf_tls_pkt_map_lookup_elem(&zero);
            if (output == NULL) return TC_ACT_UNSPEC;

            output->hello_len = tls_header.length;
            output->len = skb->len;
            output->uid = bpf_get_socket_uid(skb);
            bpf_skb_load_bytes(skb, IP_ETH_OFF_SRC, &output->local_ip4, sizeof(output->local_ip4));
            bpf_skb_load_bytes(skb, IP_ETH_OFF_DST, &output->remote_ip4, sizeof(output->remote_ip4));
            output->timestamp = bpf_ktime_get_boot_ns();
            output->remote_port = load_half(skb, TCP4_DPORT_OFF);
            output->local_port = load_half(skb, TCP4_SPORT_OFF);
            output->type = pkt_flow;
            output->data_len = 0;

            uint8_t* pcursor = (uint8_t*)output->hello_data;
            int offset = 0;

            #pragma unroll (MAX_PKT_SEGMENTS)
            for (int i = 0; i < MAX_PKT_SEGMENTS; i++) {
                offset = i * BYTES_PER_SEGMENT;
                pcursor = (uint8_t*)(output->hello_data + offset);
                if (bpf_skb_load_bytes(skb, offset + TLS_OFFSET, pcursor, PKT_SEGMENT_SIZE_4) == 0) {
                    output->data_len += PKT_SEGMENT_SIZE_4;
                }
                else if (bpf_skb_load_bytes(skb, offset + TLS_OFFSET, pcursor, PKT_SEGMENT_SIZE_3) == 0) {
                    output->data_len += PKT_SEGMENT_SIZE_3;
                }
                else if (bpf_skb_load_bytes(skb, offset + TLS_OFFSET, pcursor, PKT_SEGMENT_SIZE_2) == 0) {
                    output->data_len += PKT_SEGMENT_SIZE_2;
                }
                else if (bpf_skb_load_bytes(skb, offset + TLS_OFFSET, pcursor, PKT_SEGMENT_SIZE_1) == 0) {
                    output->data_len += PKT_SEGMENT_SIZE_1;
                }
                if (offset + TLS_OFFSET + 1 >= skb->len /* || offset + TLS_OFFSET + 1 >= hello_len*/) {
                    break;
                }
            }
            bpf_tls_pkt_ringbuf_output(output);
#endif
        }
    }
    return TC_ACT_UNSPEC;
}

DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/tls_pkt", AID_ROOT, AID_NET_ADMIN, sched_cls_ingress_tls_pkt)
(struct __sk_buff* skb) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] schedcls/ingress/tls_pkt");
#endif
    return check_tls_hello_packet(skb, NET_INGRESS);
}

DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/tls_pkt", AID_ROOT, AID_NET_ADMIN, sched_cls_egress_tls_pkt)
(struct __sk_buff* skb) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] schedcls/egress/tls_pkt");
#endif
    return check_tls_hello_packet(skb, NET_EGRESS);
}

LICENSE("GPL");