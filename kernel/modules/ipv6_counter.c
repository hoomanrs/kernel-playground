#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/hashtable.h>  // Project requirement: Hash map
#include <linux/proc_fs.h>    // Project requirement: /proc export
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hooman Rostami");
MODULE_DESCRIPTION("IPv6 /64 Hash Map Atomic Counter");
MODULE_VERSION("4.1");

// 1. OUR DATA STRUCTURE
// This holds the /64 prefix and the atomic 64-bit integer counter.
struct prefix_entry {
    struct in6_addr prefix; 
    atomic64_t count;       // Thread-safe atomic counter for this prefix
    struct hlist_node node; 
};

// Create the Hash Table (8 bits = 256 buckets)
static DEFINE_HASHTABLE(ipv6_hash_table, 8);

// Create ONE lock to protect the entire hash table from allocation/insertion conflicts
static DEFINE_SPINLOCK(table_lock);

static struct nf_hook_ops nfho;

// 2. THE NETWORK HOOK
static unsigned int my_hook_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) 
{
    struct ipv6hdr _ipv6h, *ipv6_header;
    struct in6_addr prefix_64 = {0}; // Initialize to all zeros
    struct prefix_entry *entry;
    u32 hash_key;
    bool found = false;

    // Ignore non-IPv6 packets
    if (!skb || ntohs(skb->protocol) != ETH_P_IPV6) 
        return NF_ACCEPT;

    // Safely look at the IPv6 header
    ipv6_header = skb_header_pointer(skb, skb_network_offset(skb), sizeof(_ipv6h), &_ipv6h);
    if (!ipv6_header) 
        return NF_ACCEPT;

    // --- PROJECT REQUIREMENT: Isolate the /64 prefix ---
    // Copy the first 8 bytes (64 bits) of the source address
    memcpy(prefix_64.s6_addr, ipv6_header->saddr.s6_addr, 8);

    // Create a hash key based on those 8 bytes
    hash_key = jhash(prefix_64.s6_addr, 8, 0);

    // LOCK THE DOOR: Stop other packets from editing the table structure while we work
    spin_lock_bh(&table_lock);

    // Search the hash map to see if we already know this prefix
    hash_for_each_possible(ipv6_hash_table, entry, node, hash_key) {
        if (memcmp(entry->prefix.s6_addr, prefix_64.s6_addr, 8) == 0) {
            atomic64_inc(&entry->count); // Found it! Safely increment the atomic counter.
            found = true;
            break;
        }
    }

    // If we didn't find it, create a new entry
    if (!found) {
        entry = kmalloc(sizeof(struct prefix_entry), GFP_ATOMIC);
        if (entry) {
            entry->prefix = prefix_64;
            atomic64_set(&entry->count, 1); // First packet! Set to 1 atomically.
            hash_add(ipv6_hash_table, &entry->node, hash_key); // Add to hash map
        }
    }

    // UNLOCK THE DOOR: Let other packets in
    spin_unlock_bh(&table_lock);

    return NF_ACCEPT; 
}

// 3. READING THE /PROC FILE
static int proc_show(struct seq_file *m, void *v) {
    int bucket;
    struct prefix_entry *entry;

    seq_printf(m, "Subnet Prefix (/64)                     | Packets\n");
    seq_printf(m, "--------------------------------------------------\n");

    // Lock the table so structural modifications don't happen during read
    spin_lock_bh(&table_lock);
    
    // Go through every item in the hash map and print it
    hash_for_each(ipv6_hash_table, bucket, entry, node) {
        seq_printf(m, "%pI6c/64                          | %lld\n", 
                   &entry->prefix, atomic64_read(&entry->count)); // Safely read the atomic variable
    }
    
    spin_unlock_bh(&table_lock);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open    = proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

// 4. MODULE STARTUP
static int __init mod_init(void) 
{
    hash_init(ipv6_hash_table);
    proc_create("ipv6_prefix_counters", 0444, NULL, &proc_fops);

    // --- PROJECT REQUIREMENT: Hook in PRE_ROUTING ---
    nfho.hook     = my_hook_fn;
    nfho.hooknum  = NF_INET_PRE_ROUTING;
    nfho.pf       = NFPROTO_IPV6;
    nfho.priority = NF_IP6_PRI_FIRST;
    
    nf_register_net_hook(&init_net, &nfho);
    pr_info("Atomic IPv6 Hash Counter loaded.\n");
    return 0;
}

// 5. MODULE SHUTDOWN
static void __exit mod_exit(void) 
{
    int bucket;
    struct prefix_entry *entry;
    struct hlist_node *tmp;

    // 1. Stop intercepting packets
    nf_unregister_net_hook(&init_net, &nfho);
    
    // 2. Remove the user file
    remove_proc_entry("ipv6_prefix_counters", NULL);

    // 3. Delete everything in the hash table to free memory
    spin_lock_bh(&table_lock);
    hash_for_each_safe(ipv6_hash_table, bucket, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
    spin_unlock_bh(&table_lock);

    pr_info("Atomic IPv6 Hash Counter unloaded safely.\n");
}

module_init(mod_init);
module_exit(mod_exit);
