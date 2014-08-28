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

#define DHCPV6_ENT_NO 30462
#define DHCPV6_ENT_TYPE 1

#define DHCPV6_HDR_LEN 4
#define DHCPV6_OPT_LEN 4
struct __attribute__((__packed__)) dhcp6_hdr 
{
  __u8 message_type;
  __u8 transaction_id[3];
};
struct __attribute__((__packed__)) dhcp6_option_hdr
{
  __u16 option_id;
  __u16 option_length;
};
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

// Check proto is IPv6 & extract IPv6 Header if so
  if (skb->protocol != htons(ETH_P_IPV6)) return NF_ACCEPT;
  ip6 = ipv6_hdr(skb);
  // Check IPv6 proto is 17, UDP & extract UDP Header if so
  // retrieve usefull sport, dport & datagram length
  if(ip6->nexthdr != 17) return NF_ACCEPT;
  printk(KERN_NOTICE "DHCPv6 Hook : Received IPv6 UDP packet.\n");
  udph = (struct udphdr*)skb_transport_header(skb);
  source_port=(unsigned int)ntohs(udph->source);
  dest_port=(unsigned int)ntohs(udph->dest);
  udplen=(unsigned int)ntohs(udph->len);
  printk(KERN_NOTICE "DHCPv6 Hook : Source port is %u, dest port is %u.\n",source_port,dest_port);
  if(source_port != 547) return NF_ACCEPT;
  if(dest_port != 546) return NF_ACCEPT;
  printk(KERN_NOTICE "DHCPv6 Hook : Packet is DHCPv6 response from server.\n");
  dhcp6hdr = (struct dhcp6_hdr*)(skb_transport_header(skb) + 8);
  messagetype = (__u8)dhcp6hdr->message_type;
  printk(KERN_NOTICE "DHCPv6 Hook : Header start : %x.\n", (unsigned int)&dhcp6hdr);
  printk(KERN_NOTICE "DHCPv6 Hook : Message type is %u.\n", messagetype);
  if(messagetype != DHCPV6_MSG_REPLY) return NF_ACCEPT;
  printk(KERN_NOTICE "DHCPv6 Hook : Message is type Reply. Checking options received.\n");
  current_pos = 8 + DHCPV6_HDR_LEN;
  while(current_pos < udplen)
  {
    dhcp6opt = (struct dhcp6_option_hdr*)(skb_transport_header(skb) + current_pos);
    optiontype = (__u16)ntohs(dhcp6opt->option_id);
    optionlen = (__u16)ntohs(dhcp6opt->option_length);
    printk(KERN_NOTICE "DHCPv6 Hook : Found option %u, length %u.\n",(unsigned int)optiontype, (unsigned int)optionlen);
    if(optiontype == DHCPV6_OPT_IA_PD)
    {
      printk(KERN_NOTICE "DHCPv6 Hook : Treating Prefix delegation option separatly from DHCPv6 client.\n");
      dhcp6iapd = (struct dhcp6_ia_pd*)(skb_transport_header(skb) + current_pos + DHCPV6_HDR_LEN);
      dpreflen = (__u8)dhcp6iapd->ia_pd_prefix_length;
      dpref = (struct in6_addr)dhcp6iapd->ia_pd_prefix;
      printk(KERN_NOTICE "DHCPv6 Hook : Delegated Prefix length is %u.\n", (unsigned int)dpreflen);
      int nb = dpreflen / 8;
      int i = 0;
      printk(KERN_NOTICE "DHCPv6 Hook : Prefix is ");
      while(i<nb)
      {
        printk("%x:",dpref.s6_addr[i]);
        i++;
      }
      printk(":/%u\n",(unsigned int)dpreflen);
    }
    current_pos += DHCPV6_OPT_LEN + optionlen;
  }
  printk(KERN_NOTICE "DHCPv6 Hook : End of option list.\n");
  return NF_ACCEPT;
}

static struct nf_hook_ops dhcp6_hook_ops;

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
  

static void __exit dhcp6_hook_end(void)
{
  nf_unregister_hook(&dhcp6_hook_ops);
  printk(KERN_INFO "DHCPv6 Hook: module removed\n");
}

module_init(dhcp6_hook_init);
module_exit(dhcp6_hook_end);
