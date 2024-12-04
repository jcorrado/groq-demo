// eBPF program to embed two chars from a static string, in series, in
// the IP ID field.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#define IPPROTO_TCP 6

// Define the string to embed. It must be an even number of chars.
#define STRING_LENGTH 12
const char embed_string[STRING_LENGTH] = "Groq+Jereme+";

// Define a map to store the current index of embed_string.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);  // Only one key for global state
    __type(key, __u32);
    __type(value, __u32);
} state_map SEC(".maps");

SEC("tc")
int embed_ip_id(struct __sk_buff *skb) {
    void *data = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;

    // Validate packet is large enough to contain an Ethernet frame.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("Packet too short for Ethernet header\n");
        return BPF_OK;
    }

    // Check datagram min size and filter to only TCP.
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP) {
        bpf_printk("Non-TCP or malformed packet\n");
        return BPF_OK;
    }

    // Set DF bit in the IP header (bit 14 of the Flags field).
    ip->frag_off |= __constant_htons(0x4000);

    // Retrieve the current string index from our map.
    __u32 key = 0;
    __u32 *index = bpf_map_lookup_elem(&state_map, &key);
    if (!index) {
        bpf_printk("Failed to retrieve state from map\n");
        return BPF_OK;
    }

    // Verify index is within bounds and that we have enough space for
    // two chars.
    if (*index >= STRING_LENGTH - 1) {
        bpf_printk("Index out of bounds: resetting to 0\n");
        *index = 0;
    }

    // Copy the string to a stack-based buffer.
    char local_string[STRING_LENGTH];
    #pragma unroll
    for (int i = 0; i < STRING_LENGTH; i++) {
        local_string[i] = embed_string[i];
    }

    // Embed chars in the IP ID field.
    char char1 = local_string[*index];
    char char2 = local_string[(*index + 1) % STRING_LENGTH];
    unsigned short embed_data = ((unsigned short)char1 << 8) | (unsigned short)char2;
    ip->id = __constant_htons(embed_data);

    // Update the IP checksum
    bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), 0, ip->id, 0);

    // Update the index in the map to point to the next char pair.
    __u32 next_index = (*index + 2) % STRING_LENGTH;
    bpf_map_update_elem(&state_map, &key, &next_index, BPF_ANY);

    // Log the embedded chars for debugging.
    bpf_printk("Embedded '%c%c' in IP ID field\n", char1, char2);

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
