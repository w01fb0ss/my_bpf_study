#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// static bool is_ICMP(void *data_begin, void *data_end)
// {
//     // sudo cat /sys/kernel/debug/tracing/trace_pipe
//     // bpf_printk("Entering is_ICMP\n");
//     struct ethhdr *eth = data_begin;
// 
//     if ((void *)(eth + 1) > data_end)
//         return false;
// 
//     if (eth->h_proto == bpf_htons(ETH_P_IP))
//     {
//         struct iphdr *iph = (struct iphdr *)(eth + 1);
//         if ((void *)(iph + 1) > data_end)
//             return false;
// 
//         if (iph->protocol == IPPROTO_ICMP)
//             return true;
//     }
//     else if (eth->h_proto == bpf_htons(ETH_P_8021Q))
//     {
//         return false;
//     }
//     return false;
// }

SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

// if (is_ICMP(data, data_end))
//       return XDP_DROP;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
    if (ip->protocol == IPPROTO_ICMP)
    {
        // bpf_printk("PING");
	return XDP_DROP;
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
