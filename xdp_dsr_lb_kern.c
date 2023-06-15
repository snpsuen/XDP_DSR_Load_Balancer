#include "xdp_dsr_lb_kern.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))
#define VIP_ADDRESS(x) (unsigned int)(192 + (168 << 8) + (25 << 16) + (x << 24))

#define LB 2
#define BACKEND_A 3
#define BACKEND_B 4
#define VIP 10

struct five_tuple {
    __u8  protocol;
    __u32 ip_source;
    __u32 ip_destination;
    __u16 port_source;
    __u16 port_destination;
};

struct bpf_map_def SEC("maps") forward_flow = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct five_tuple),
    .value_size  = sizeof(__u8),
    .max_entries = 100000,
    .map_flags   = BPF_F_NO_PREALLOC,
};

SEC("xdp_dsr_lb")
int xdp_dsr_load_balancer(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct five_tuple forward_key = {};
    __u8* forward_backend;
    __u16 return_key;
    __u32* return_addr;
    __u8 backend;
    __u16 srcport;
    __u32 srcaddr;
    struct bpf_fib_lookup fib_params = {};
    long rc;

    bpf_printk("got something");
    struct ethhdr* eth = data;
    if ((void*)eth + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr* iph = (void*)eth + sizeof(struct ethhdr);
    if ((void*)iph + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr* tcph = (void*)iph + sizeof(struct iphdr);
    if ((void*)tcph + sizeof(struct tcphdr) > data_end)
        return XDP_ABORTED;

    bpf_printk("Got TCP packet travelling from port %d to %d", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
    bpf_printk("Got TCP packet travelling from IP %x to %x", iph->saddr, iph->daddr);
    if (iph->daddr == VIP_ADDRESS(VIP)) {
        bpf_printk("Packet sent from the client %x", iph->saddr);
        bpf_printk("Packet with tcp source port %d", bpf_ntohs(tcph->source));
        bpf_printk("Packet with tcp destination port %d", bpf_ntohs(tcph->dest));
        
        forward_key.protocol = iph->protocol;
        forward_key.ip_source = iph->saddr;
        forward_key.ip_destination = iph->daddr;
        forward_key.port_source = bpf_ntohs(tcph->source);
        forward_key.port_destination = bpf_ntohs(tcph->dest);
            
        forward_backend = bpf_map_lookup_elem(&forward_flow, &forward_key);
        if (forward_backend == NULL) {
            backend = BACKEND_A;
            if (bpf_get_prandom_u32() % 2)
                backend = BACKEND_B;
            
            bpf_printk("Add a new entry to the forward flow table for backend %x", IP_ADDRESS(backend));
            bpf_map_update_elem(&forward_flow, &forward_key, &backend, BPF_ANY);  
        }
        else {
            bpf_printk("Located backend %x from an existing entry in the forward flow table ", IP_ADDRESS(*forward_backend));
            backend = *forward_backend;
        }
        
        bpf_printk("Packet to be forwrded to backend %x", IP_ADDRESS(backend));        
        eth->h_dest[5] = backend;
        eth->h_source[5] = LB;
        
        bpf_printk("Before XDP_TX, iph->saddr = %x, iph->daddr = %x", iph->saddr, iph->daddr);
        bpf_printk("Before XDP_TX, eth->h_source[5] = %x, eth->h_dest[5] = %x", eth->h_source[5], eth->h_dest[5]);
        bpf_printk("Returning XDP_TX ...");
        return XDP_TX;
    }
}

char _license[] SEC("license") = "GPL";