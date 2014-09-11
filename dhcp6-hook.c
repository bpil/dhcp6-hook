#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>

#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/ip.h>
#include <net/route.h>
#include <net/ip6_route.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bpilat");

// Various DHCPv6 opt definitions (from Wide implementation)
#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547

#define DHCPV6_MSG_SOLICIT 1
#define DHCPV6_MSG_ADVERTISE 2
#define DHCPV6_MSG_REQUEST 3
#define DHCPV6_MSG_CONFIRM 4
#define DHCPV6_MSG_RENEW 5
#define DHCPV6_MSG_REBIND 6
#define DHCPV6_MSG_REPLY 7
#define DHCPV6_MSG_RELEASE 8
#define DHCPV6_MSG_DECLINE 9
#define DHCPV6_MSG_RECONFIGURE 10
#define DHCPV6_MSG_INFORMATION_REQUEST 11
#define DHCPV6_MSG_RELAY_FORW 12
#define DHCPV6_MSG_RELAY_REPL 13

#define DHCPV6_OPT_CLIENTID 1
#define DHCPV6_OPT_SERVERID 2
#define DHCPV6_OPT_IA_NA 3
#define DHCPV6_OPT_IA_ADDR 5
#define DHCPV6_OPT_ORO 6
#define DHCPV6_OPT_STATUS 13
#define DHCPV6_OPT_RELAY_MSG 9
#define DHCPV6_OPT_AUTH 11
#define DHCPV6_OPT_USER_CLASS 15
#define DHCPV6_OPT_INTERFACE_ID 18
#define DHCPV6_OPT_RECONF_MSG 19
#define DHCPV6_OPT_RECONF_ACCEPT 20
#define DHCPV6_OPT_DNS_SERVERS 23
#define DHCPV6_OPT_DNS_DOMAIN 24
#define DHCPV6_OPT_IA_PD 25
#define DHCPV6_OPT_IA_PREFIX 26
#define DHCPV6_OPT_INFO_REFRESH 32
#define DHCPV6_OPT_FQDN 39
#define DHCPV6_OPT_SOL_MAX_RT 82
#define DHCPV6_OPT_INF_MAX_RT 83

// IANA newly defined \o/
// draft-softwire-map-dhcp
#define DHCPV6_OPT_S46_RULE 89
#define DHCPV6_OPT_S46_BR 90
#define DHCPV6_OPT_S46_DMR 91
#define DHCPV6_OPT_S46_V4V6BIND 92
#define DHCPV6_OPT_S46_PORTPARAMS 93
#define DHCPV6_OPT_S46_CONT_MAPE 94
#define DHCPV6_OPT_S46_CONT_MAPT 95
#define DHCPV6_OPT_S46_CONT_LW 96

#define DHCPV6_ENT_NO 30462
#define DHCPV6_ENT_TYPE 1

#define DHCPV6_HDR_LEN 4
#define DHCPV6_OPT_LEN 4

// Crude Ceil macro
// No access to math.h (module)
#define CEILING(X) (X-(int)(X) > 0 ? (int)(X+1) : (int)(X))

// DHCPv6 Header structure
// RFC 3315
struct __attribute__((__packed__)) dhcp6_hdr 
{
  __u8 message_type;
  __u8 transaction_id[3];
};

// DHCPv6 Option Header structure
// RFC 3315
struct __attribute__((__packed__)) dhcp6_option_hdr
{
  __u16 option_id;
  __u16 option_length;
};

// DHCPv6 IA_NA structure
// RFC 3315
struct __attribute__((__packed__)) dhcp6_ia_na
{
  __u32 iaid;
  __u32 time1;
  __u32 time2;
  __u16 ia_na_option;
  __u16 ia_na_option_length;
  struct in6_addr ia_na_address;
  __u32 ia_na_prefered_lifetime;
  __u32 ia_na_valid_lifetime;
};

// DHCPv6 IA_PD Prefix Delegation option structure
// RFC 3633
struct __attribute__((__packed__)) dhcp6_ia_pd
{
  __u32 iaid;
  __u32 t1;
  __u32 t2;
  __u16 ia_pd_option;
  __u16 ia_pd_option_length;
  __u32 ia_pd_prefered_lifetime;
  __u32 ia_pd_valid_lifetime;
  __u8 ia_pd_prefix_length;
  struct in6_addr ia_pd_prefix;
};

// DHCPv6 S46 Rule Option
// draft-ietf-softwire-map-dhcp
// variable length IPv6 prefix is not listed
struct __attribute__((__packed__)) dhcp6_s46_rule
{
  __u8 flags;
  __u8 ea_len;
  __u8 prefix4_len;
  __u32 ipv4_prefix;
  __u8 prefix6_len;
};

// DHCPv6 S46 DMR Option
// draft-ietf-softwire-map-dhcp
// variable length IPv6 prefix is not listed
struct __attribute__((__packed__)) dhcp6_s46_dmr
{
  __u8 dmr_prefix_len;
};

// DHCPv6 S46 Port Params Option
// draft-ietf-softwire-map-dhcp
struct __attribute__((__packed__)) dhcp6_s46_ports
{
  __u8 offset;
  __u8 psid_len;
  __u16 psid;
};

// Main Hook function
// Check incoming packets for protocol type, port number, and DHCP options
static unsigned dhcp6_hook_input_handle( 
  const struct nf_hook_ops *ops,
  struct sk_buff *skb,
  const struct net_device *in,
  const struct net_device *out,
  int (*okfn)(struct skbuff *))
{
  struct ipv6hdr *ip6;
  struct sk_buff *nskb;
  struct udphdr *udph;
  unsigned int udplen;
  unsigned int source_port;
  unsigned int dest_port;
  struct dhcp6_hdr *dhcp6hdr;
  struct dhcp6_option_hdr *dhcp6opt;
  struct dhcp6_ia_pd *dhcp6iapd;
  __u8 messagetype;
  __u16 optiontype;
  __u16 optionlen;
  unsigned int current_pos;
  __u8 dpreflen;
  struct in6_addr dpref;
  struct dhcp6_s46_rule *maprule;
  struct dhcp6_s46_ports *portsrule;
  __u32 ruleipv4prefix;
  __u8 ruleipv4prefixlen;
  __u8 ruleipv6prefixlen;
  struct in6_addr* ruleipv6prefix = kmalloc(sizeof *ruleipv6prefix, GFP_KERNEL);
  // usual incr variables
  int nb;
  int i;
  
  // if Ether Proto is not IPv6, immediatly accept packet & exit
  if (skb->protocol != htons(ETH_P_IPV6)) return NF_ACCEPT;
  
  // point ip6 to IPv6 Header
  ip6 = ipv6_hdr(skb);
  
  // If IPv6 Next Header field is not 17 (UDP)
  // immediatly accept packet & exit
  if(ip6->nexthdr != 17) return NF_ACCEPT;
  
  
  // printk(KERN_NOTICE "DHCPv6 Hook : Received IPv6 UDP packet.\n");
  
  // point udph to UDP Header
  udph = (struct udphdr*)skb_transport_header(skb);
  
  // Get UDP source and dest ports, and packet length
  source_port=(unsigned int)ntohs(udph->source);
  dest_port=(unsigned int)ntohs(udph->dest);
  udplen=(unsigned int)ntohs(udph->len);
  // printk(KERN_NOTICE "DHCPv6 Hook : Source port is %u, dest port is %u.\n",source_port,dest_port);
  
  // If ports are not DHCPv6, immediatly accept packet & exit
  if(source_port != 547) return NF_ACCEPT;
  if(dest_port != 546) return NF_ACCEPT;
  // printk(KERN_NOTICE "DHCPv6 Hook : Packet is DHCPv6 response from server.\n");
  
  // Point dhcp6hdr to DHCPv6 Header (UDP Header length is 8 bytes)
  dhcp6hdr = (struct dhcp6_hdr*)(skb_transport_header(skb) + 8);
  
  // If Message is not REPLY, immediatly accept packet & exit
  // WARNING : Does not cover all RFC3315 cases!
  messagetype = (__u8)dhcp6hdr->message_type;
  if(messagetype != DHCPV6_MSG_REPLY) return NF_ACCEPT;
  
  printk(KERN_NOTICE "DHCPv6 Hook : DHCPv6 REPLY received.\n");
  
  // current_pos is the offset from UDP Header position while scanning the packet
  // We start just after DHCPv6 Header (UDP Header length is still 8 bytes)
  current_pos = 8 + DHCPV6_HDR_LEN;
  
  while(current_pos < udplen)
  {
    // point dhcp6opt to next DHCPv6 Option Header
    // Get Type and option length
    dhcp6opt = (struct dhcp6_option_hdr*)(skb_transport_header(skb) + current_pos);
    optiontype = (__u16)ntohs(dhcp6opt->option_id);
    optionlen = (__u16)ntohs(dhcp6opt->option_length);

    // If Prefix Delegation Option, get Prefix and use it
    // Currently only log the prefix to syslog
    if(optiontype == DHCPV6_OPT_IA_PD)
    {
      printk(KERN_NOTICE "DHCPv6 Hook : Treating Prefix delegation option separatly from DHCPv6 client.\n");
      dhcp6iapd = (struct dhcp6_ia_pd*)(skb_transport_header(skb) + current_pos + DHCPV6_HDR_LEN);
      dpreflen = (__u8)dhcp6iapd->ia_pd_prefix_length;
      dpref = (struct in6_addr)dhcp6iapd->ia_pd_prefix;
      printk(KERN_NOTICE "DHCPv6 Hook : Delegated Prefix length is %u.\n", (unsigned int)dpreflen);
      nb = dpreflen / 8;
      i = 0;
      printk(KERN_NOTICE "DHCPv6 Hook : Prefix is ");
      while(i<nb)
      {
        printk("%x:",dpref.s6_addr[i]);
        i++;
      }
      printk(":/%u\n",(unsigned int)dpreflen);
    }
    
    // Case MAP-T Container
    // We do not check if container follows the correct syntax
    if(optiontype == DHCPV6_OPT_S46_CONT_MAPT)
    {
      printk(KERN_NOTICE "DHCPv6 Hook : Received MAP-T Container Option.\n");
      optionlen = 0;
    }
    
    // Case MAP Rule
    if(optiontype == DHCPV6_OPT_S46_RULE)
    {
      maprule = (struct dhcp6_s46_rule*)(skb_transport_header(skb) + current_pos);
      ruleipv4prefix = maprule->ipv4_prefix;
      ruleipv4prefixlen = maprule->prefix4_len;
      ruleipv6prefixlen = maprule->prefix6_len;
      //ruleipv6prefix = (struct in6_addr) &maprule;
      memcpy(ruleipv6prefix, (maprule + 6), CEILING(ruleipv6prefixlen / 8));
    }
    // move pointer to next DHCPv6 option
    current_pos += DHCPV6_OPT_LEN + optionlen;
  }
  return NF_ACCEPT;
}

static struct nf_hook_ops dhcp6_hook_ops;

// Register hook function to NF 
static int __init dhcp6_hook_init(void) 
{
  int err = 0;
  dhcp6_hook_ops.hook = (nf_hookfn *)dhcp6_hook_input_handle;
  dhcp6_hook_ops.pf = NFPROTO_IPV6;
  dhcp6_hook_ops.hooknum = NF_INET_LOCAL_IN;
  err = nf_register_hook(&dhcp6_hook_ops);
  if(err) {
    printk(KERN_INFO "DHCPv6 Hook : Can't register hook.\n");
  }
  printk(KERN_INFO "DHCPv6 Hook: module loaded\n");
  return 0;
}
  
// Unregister hook function
static void __exit dhcp6_hook_end(void)
{
  nf_unregister_hook(&dhcp6_hook_ops);
  printk(KERN_INFO "DHCPv6 Hook: module removed\n");
}

module_init(dhcp6_hook_init);
module_exit(dhcp6_hook_end);
