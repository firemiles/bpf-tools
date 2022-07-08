/**
 * Copyright 2022 firemiles
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#include <net/ipv6.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define printk(fmt, ...)    \
({  char ___fmt[] = fmt;    \
	bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);\
})

//#include <net/netfilter/nf_conntrack_common.h>
#define IP_CT_ESTABLISHED	0
#define IP_CT_RELATED		1
#define IP_CT_NEW		2

SEC("ct_lookup")
int _ct_lookup(struct __sk_buff *skb)
{
	int ret, flags;
	__u64 proto;
	struct bpf_sock_tuple tuple;

	proto = load_half(skb, 12);
	if (proto != ETH_P_IP) {
		return TC_ACT_OK;
	} else {
		__u64 ip_proto = load_byte(skb, 14 +
					   offsetof(struct iphdr, protocol));
		if (ip_proto != IPPROTO_ICMP)
			return TC_ACT_OK;
	}

	__builtin_memset(&info, 0x0, sizeof(info));


	ret = bpf_skb_ct_lookup(skb, &tuple, 0);
	if (ret < 0) {
		printk("ct_lookup failed\n");
		return TC_ACT_OK;
	}

	printk("ct_lookup: zone: %d state: %d mark: %x",
		info.zone_id, info.ct_state, info.mark_value);

	if (info.ct_state == IP_CT_ESTABLISHED) {
		printk("allow established connection\n");
		return TC_ACT_OK;
	} else if (info.ct_state == IP_CT_NEW) {
		printk("drop new connection\n");
		return TC_ACT_SHOT;
	} else {
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
