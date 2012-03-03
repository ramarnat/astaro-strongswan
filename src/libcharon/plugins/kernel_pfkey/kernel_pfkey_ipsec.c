/*
 * Copyright (C) 2008-2009 Tobias Brunner
 * Copyright (C) 2008 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <sys/types.h>
#include <sys/socket.h>

#ifdef __FreeBSD__
#include <limits.h> /* for LONG_MAX */
#endif

#ifdef HAVE_NET_PFKEYV2_H
#include <net/pfkeyv2.h>
#else
#include <stdint.h>
#include <linux/pfkeyv2.h>
#endif

#ifdef SADB_X_EXT_NAT_T_TYPE
#define HAVE_NATT
#endif

#ifdef HAVE_NETIPSEC_IPSEC_H
#include <netipsec/ipsec.h>
#elif defined(HAVE_NETINET6_IPSEC_H)
#include <netinet6/ipsec.h>
#else
#include <linux/ipsec.h>
#endif

#ifdef HAVE_NATT
#ifdef HAVE_LINUX_UDP_H
#include <linux/udp.h>
#else
#include <netinet/udp.h>
#endif /*HAVE_LINUX_UDP_H*/
#endif /*HAVE_NATT*/

#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "kernel_pfkey_ipsec.h"

#include <daemon.h>
#include <utils/host.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/acquire_job.h>
#include <processing/jobs/migrate_job.h>
#include <processing/jobs/rekey_child_sa_job.h>
#include <processing/jobs/delete_child_sa_job.h>
#include <processing/jobs/update_sa_job.h>

/** non linux specific */
#ifndef IPPROTO_COMP
#define IPPROTO_COMP IPPROTO_IPCOMP
#endif

#ifndef SADB_X_AALG_SHA2_256HMAC
#define SADB_X_AALG_SHA2_256HMAC SADB_X_AALG_SHA2_256
#define SADB_X_AALG_SHA2_384HMAC SADB_X_AALG_SHA2_384
#define SADB_X_AALG_SHA2_512HMAC SADB_X_AALG_SHA2_512
#endif

#ifndef SADB_X_EALG_AESCBC
#define SADB_X_EALG_AESCBC SADB_X_EALG_AES
#endif

#ifndef SADB_X_EALG_CASTCBC
#define SADB_X_EALG_CASTCBC SADB_X_EALG_CAST128CBC
#endif

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#define SOL_IPV6 IPPROTO_IPV6
#endif

/** from linux/in.h */
#ifndef IP_IPSEC_POLICY
#define IP_IPSEC_POLICY 16
#endif

/** missing on uclibc */
#ifndef IPV6_IPSEC_POLICY
#define IPV6_IPSEC_POLICY 34
#endif

/** default priority of installed policies */
#define PRIO_LOW 3000
#define PRIO_HIGH 2000

#ifdef __APPLE__
/** from xnu/bsd/net/pfkeyv2.h */
#define SADB_X_EXT_NATT 0x002
	struct sadb_sa_2 {
		struct sadb_sa	sa;
		u_int16_t		sadb_sa_natt_port;
		u_int16_t		sadb_reserved0;
		u_int32_t		sadb_reserved1;
	};
#endif

/** buffer size for PF_KEY messages */
#define PFKEY_BUFFER_SIZE 4096

/** PF_KEY messages are 64 bit aligned */
#define PFKEY_ALIGNMENT 8
/** aligns len to 64 bits */
#define PFKEY_ALIGN(len) (((len) + PFKEY_ALIGNMENT - 1) & ~(PFKEY_ALIGNMENT - 1))
/** calculates the properly padded length in 64 bit chunks */
#define PFKEY_LEN(len) ((PFKEY_ALIGN(len) / PFKEY_ALIGNMENT))
/** calculates user mode length i.e. in bytes */
#define PFKEY_USER_LEN(len) ((len) * PFKEY_ALIGNMENT)

/** given a PF_KEY message header and an extension this updates the length in the header */
#define PFKEY_EXT_ADD(msg, ext) ((msg)->sadb_msg_len += ((struct sadb_ext*)ext)->sadb_ext_len)
/** given a PF_KEY message header this returns a pointer to the next extension */
#define PFKEY_EXT_ADD_NEXT(msg) ((struct sadb_ext*)(((char*)(msg)) + PFKEY_USER_LEN((msg)->sadb_msg_len)))
/** copy an extension and append it to a PF_KEY message */
#define PFKEY_EXT_COPY(msg, ext) (PFKEY_EXT_ADD(msg, memcpy(PFKEY_EXT_ADD_NEXT(msg), ext, PFKEY_USER_LEN(((struct sadb_ext*)ext)->sadb_ext_len))))
/** given a PF_KEY extension this returns a pointer to the next extension */
#define PFKEY_EXT_NEXT(ext) ((struct sadb_ext*)(((char*)(ext)) + PFKEY_USER_LEN(((struct sadb_ext*)ext)->sadb_ext_len)))
/** given a PF_KEY extension this returns a pointer to the next extension also updates len (len in 64 bit words) */
#define PFKEY_EXT_NEXT_LEN(ext,len) ((len) -= (ext)->sadb_ext_len, PFKEY_EXT_NEXT(ext))
/** true if ext has a valid length and len is large enough to contain ext (assuming len in 64 bit words) */
#define PFKEY_EXT_OK(ext,len) ((len) >= PFKEY_LEN(sizeof(struct sadb_ext)) && \
				(ext)->sadb_ext_len >= PFKEY_LEN(sizeof(struct sadb_ext)) && \
				(ext)->sadb_ext_len <= (len))

typedef struct private_kernel_pfkey_ipsec_t private_kernel_pfkey_ipsec_t;

/**
 * Private variables and functions of kernel_pfkey class.
 */
struct private_kernel_pfkey_ipsec_t
{
	/**
	 * Public part of the kernel_pfkey_t object.
	 */
	kernel_pfkey_ipsec_t public;

	/**
	 * mutex to lock access to various lists
	 */
	mutex_t *mutex;

	/**
	 * List of installed policies (policy_entry_t)
	 */
	linked_list_t *policies;

	/**
	 * whether to install routes along policies
	 */
	bool install_routes;

	/**
	 * job receiving PF_KEY events
	 */
	callback_job_t *job;

	/**
	 * mutex to lock access to the PF_KEY socket
	 */
	mutex_t *mutex_pfkey;

	/**
	 * PF_KEY socket to communicate with the kernel
	 */
	int socket;

	/**
	 * PF_KEY socket to receive acquire and expire events
	 */
	int socket_events;

	/**
	 * sequence number for messages sent to the kernel
	 */
	int seq;
};

typedef struct route_entry_t route_entry_t;

/**
 * installed routing entry
 */
struct route_entry_t {
	/** Name of the interface the route is bound to */
	char *if_name;

	/** Source ip of the route */
	host_t *src_ip;

	/** gateway for this route */
	host_t *gateway;

	/** Destination net */
	chunk_t dst_net;

	/** Destination net prefixlen */
	u_int8_t prefixlen;
};

/**
 * destroy an route_entry_t object
 */
static void route_entry_destroy(route_entry_t *this)
{
	free(this->if_name);
	DESTROY_IF(this->src_ip);
	DESTROY_IF(this->gateway);
	chunk_free(&this->dst_net);
	free(this);
}

typedef struct policy_entry_t policy_entry_t;

/**
 * installed kernel policy.
 */
struct policy_entry_t {

	/** reqid of this policy */
	u_int32_t reqid;

	/** index assigned by the kernel */
	u_int32_t index;

	/** direction of this policy: in, out, forward */
	u_int8_t direction;

	/** parameters of installed policy */
	struct {
		/** subnet and port */
		host_t *net;
		/** subnet mask */
		u_int8_t mask;
		/** protocol */
		u_int8_t proto;
	} src, dst;

	/** associated route installed for this policy */
	route_entry_t *route;

	/** by how many CHILD_SA's this policy is used */
	u_int refcount;
};

/**
 * create a policy_entry_t object
 */
static policy_entry_t *create_policy_entry(traffic_selector_t *src_ts,
		traffic_selector_t *dst_ts, policy_dir_t dir, u_int32_t reqid)
{
	policy_entry_t *policy = malloc_thing(policy_entry_t);
	policy->reqid = reqid;
	policy->index = 0;
	policy->direction = dir;
	policy->route = NULL;
	policy->refcount = 0;

	src_ts->to_subnet(src_ts, &policy->src.net, &policy->src.mask);
	dst_ts->to_subnet(dst_ts, &policy->dst.net, &policy->dst.mask);

	/* src or dest proto may be "any" (0), use more restrictive one */
	policy->src.proto = max(src_ts->get_protocol(src_ts), dst_ts->get_protocol(dst_ts));
	policy->src.proto = policy->src.proto ? policy->src.proto : IPSEC_PROTO_ANY;
	policy->dst.proto = policy->src.proto;

	return policy;
}

/**
 * destroy a policy_entry_t object
 */
static void policy_entry_destroy(policy_entry_t *this)
{
	DESTROY_IF(this->src.net);
	DESTROY_IF(this->dst.net);
	if (this->route)
	{
		route_entry_destroy(this->route);
	}
	free(this);
}

/**
 * compares two policy_entry_t
 */
static inline bool policy_entry_equals(policy_entry_t *current, policy_entry_t *policy)
{
	return current->direction == policy->direction &&
		   current->src.proto == policy->src.proto &&
		   current->dst.proto == policy->dst.proto &&
		   current->src.mask == policy->src.mask &&
		   current->dst.mask == policy->dst.mask &&
		   current->src.net->equals(current->src.net, policy->src.net) &&
		   current->dst.net->equals(current->dst.net, policy->dst.net);
}

/**
 * compare the given kernel index with that of a policy
 */
static inline bool policy_entry_match_byindex(policy_entry_t *current, u_int32_t *index)
{
	return current->index == *index;
}

typedef struct pfkey_msg_t pfkey_msg_t;

struct pfkey_msg_t
{
	/**
	 * PF_KEY message base
	 */
	struct sadb_msg *msg;

	/**
	 * PF_KEY message extensions
	 */
	union {
		struct sadb_ext *ext[SADB_EXT_MAX + 1];
		struct {
			struct sadb_ext *reserved;				/* SADB_EXT_RESERVED */
			struct sadb_sa *sa;						/* SADB_EXT_SA */
			struct sadb_lifetime *lft_current;		/* SADB_EXT_LIFETIME_CURRENT */
			struct sadb_lifetime *lft_hard;			/* SADB_EXT_LIFETIME_HARD */
			struct sadb_lifetime *lft_soft;			/* SADB_EXT_LIFETIME_SOFT */
			struct sadb_address *src;				/* SADB_EXT_ADDRESS_SRC */
			struct sadb_address *dst;				/* SADB_EXT_ADDRESS_DST */
			struct sadb_address *proxy;				/* SADB_EXT_ADDRESS_PROXY */
			struct sadb_key *key_auth;				/* SADB_EXT_KEY_AUTH */
			struct sadb_key *key_encr;				/* SADB_EXT_KEY_ENCRYPT */
			struct sadb_ident *id_src;				/* SADB_EXT_IDENTITY_SRC */
			struct sadb_ident *id_dst;				/* SADB_EXT_IDENTITY_DST */
			struct sadb_sens *sensitivity;			/* SADB_EXT_SENSITIVITY */
			struct sadb_prop *proposal;				/* SADB_EXT_PROPOSAL */
			struct sadb_supported *supported_auth;	/* SADB_EXT_SUPPORTED_AUTH */
			struct sadb_supported *supported_encr;	/* SADB_EXT_SUPPORTED_ENCRYPT */
			struct sadb_spirange *spirange;			/* SADB_EXT_SPIRANGE */
			struct sadb_x_kmprivate *x_kmprivate;	/* SADB_X_EXT_KMPRIVATE */
			struct sadb_x_policy *x_policy;			/* SADB_X_EXT_POLICY */
			struct sadb_x_sa2 *x_sa2;				/* SADB_X_EXT_SA2 */
			struct sadb_x_nat_t_type *x_natt_type;	/* SADB_X_EXT_NAT_T_TYPE */
			struct sadb_x_nat_t_port *x_natt_sport;	/* SADB_X_EXT_NAT_T_SPORT */
			struct sadb_x_nat_t_port *x_natt_dport;	/* SADB_X_EXT_NAT_T_DPORT */
			struct sadb_address *x_natt_oa;			/* SADB_X_EXT_NAT_T_OA */
			struct sadb_x_sec_ctx *x_sec_ctx;		/* SADB_X_EXT_SEC_CTX */
			struct sadb_x_kmaddress *x_kmaddress;	/* SADB_X_EXT_KMADDRESS */
		} __attribute__((__packed__));
	};
};

ENUM(sadb_ext_type_names, SADB_EXT_RESERVED, SADB_EXT_MAX,
	"SADB_EXT_RESERVED",
	"SADB_EXT_SA",
	"SADB_EXT_LIFETIME_CURRENT",
	"SADB_EXT_LIFETIME_HARD",
	"SADB_EXT_LIFETIME_SOFT",
	"SADB_EXT_ADDRESS_SRC",
	"SADB_EXT_ADDRESS_DST",
	"SADB_EXT_ADDRESS_PROXY",
	"SADB_EXT_KEY_AUTH",
	"SADB_EXT_KEY_ENCRYPT",
	"SADB_EXT_IDENTITY_SRC",
	"SADB_EXT_IDENTITY_DST",
	"SADB_EXT_SENSITIVITY",
	"SADB_EXT_PROPOSAL",
	"SADB_EXT_SUPPORTED_AUTH",
	"SADB_EXT_SUPPORTED_ENCRYPT",
	"SADB_EXT_SPIRANGE",
	"SADB_X_EXT_KMPRIVATE",
	"SADB_X_EXT_POLICY",
	"SADB_X_EXT_SA2",
	"SADB_X_EXT_NAT_T_TYPE",
	"SADB_X_EXT_NAT_T_SPORT",
	"SADB_X_EXT_NAT_T_DPORT",
	"SADB_X_EXT_NAT_T_OA",
	"SADB_X_EXT_SEC_CTX",
	"SADB_X_EXT_KMADDRESS"
);

/**
 * convert a IKEv2 specific protocol identifier to the PF_KEY sa type
 */
static u_int8_t proto_ike2satype(protocol_id_t proto)
{
	switch (proto)
	{
		case PROTO_ESP:
			return SADB_SATYPE_ESP;
		case PROTO_AH:
			return SADB_SATYPE_AH;
		case IPPROTO_COMP:
			return SADB_X_SATYPE_IPCOMP;
		default:
			return proto;
	}
}

/**
 * convert a PF_KEY sa type to a IKEv2 specific protocol identifier
 */
static protocol_id_t proto_satype2ike(u_int8_t proto)
{
	switch (proto)
	{
		case SADB_SATYPE_ESP:
			return PROTO_ESP;
		case SADB_SATYPE_AH:
			return PROTO_AH;
		case SADB_X_SATYPE_IPCOMP:
			return IPPROTO_COMP;
		default:
			return proto;
	}
}

/**
 * convert a IKEv2 specific protocol identifier to the IP protocol identifier
 */
static u_int8_t proto_ike2ip(protocol_id_t proto)
{
	switch (proto)
	{
		case PROTO_ESP:
			return IPPROTO_ESP;
		case PROTO_AH:
			return IPPROTO_AH;
		default:
			return proto;
	}
}

/**
 * convert the general ipsec mode to the one defined in ipsec.h
 */
static u_int8_t mode2kernel(ipsec_mode_t mode)
{
	switch (mode)
	{
		case MODE_TRANSPORT:
			return IPSEC_MODE_TRANSPORT;
		case MODE_TUNNEL:
			return IPSEC_MODE_TUNNEL;
#ifdef HAVE_IPSEC_MODE_BEET
		case MODE_BEET:
			return IPSEC_MODE_BEET;
#endif
		default:
			return mode;
	}
}

/**
 * convert the general policy direction to the one defined in ipsec.h
 */
static u_int8_t dir2kernel(policy_dir_t dir)
{
	switch (dir)
	{
		case POLICY_IN:
			return IPSEC_DIR_INBOUND;
		case POLICY_OUT:
			return IPSEC_DIR_OUTBOUND;
#ifdef HAVE_IPSEC_DIR_FWD
		case POLICY_FWD:
			return IPSEC_DIR_FWD;
#endif
		default:
			return IPSEC_DIR_INVALID;
	}
}

#ifdef SADB_X_MIGRATE
/**
 * convert the policy direction in ipsec.h to the general one.
 */
static policy_dir_t kernel2dir(u_int8_t  dir)
{
	switch (dir)
	{
		case IPSEC_DIR_INBOUND:
			return POLICY_IN;
		case IPSEC_DIR_OUTBOUND:
			return POLICY_OUT;
#ifdef HAVE_IPSEC_DIR_FWD
		case IPSEC_DIR_FWD:
			return POLICY_FWD;
#endif
		default:
			return dir;
	}
}
#endif /*SADB_X_MIGRATE*/

typedef struct kernel_algorithm_t kernel_algorithm_t;

/**
 * Mapping of IKEv2 algorithms to PF_KEY algorithms
 */
struct kernel_algorithm_t {
	/**
	 * Identifier specified in IKEv2
	 */
	int ikev2;

	/**
	 * Identifier as defined in pfkeyv2.h
	 */
	int kernel;
};

#define END_OF_LIST -1

/**
 * Algorithms for encryption
 */
static kernel_algorithm_t encryption_algs[] = {
/*	{ENCR_DES_IV64,				0							}, */
	{ENCR_DES,					SADB_EALG_DESCBC			},
	{ENCR_3DES,					SADB_EALG_3DESCBC			},
/*	{ENCR_RC5,					0							}, */
/*	{ENCR_IDEA,					0							}, */
	{ENCR_CAST,					SADB_X_EALG_CASTCBC			},
	{ENCR_BLOWFISH,				SADB_X_EALG_BLOWFISHCBC		},
/*	{ENCR_3IDEA,				0							}, */
/*	{ENCR_DES_IV32,				0							}, */
	{ENCR_NULL,					SADB_EALG_NULL				},
	{ENCR_AES_CBC,				SADB_X_EALG_AESCBC			},
/*	{ENCR_AES_CTR,				SADB_X_EALG_AESCTR			}, */
/*  {ENCR_AES_CCM_ICV8,			SADB_X_EALG_AES_CCM_ICV8	}, */
/*	{ENCR_AES_CCM_ICV12,		SADB_X_EALG_AES_CCM_ICV12	}, */
/*	{ENCR_AES_CCM_ICV16,		SADB_X_EALG_AES_CCM_ICV16	}, */
/*	{ENCR_AES_GCM_ICV8,			SADB_X_EALG_AES_GCM_ICV8	}, */
/*	{ENCR_AES_GCM_ICV12,		SADB_X_EALG_AES_GCM_ICV12	}, */
/*	{ENCR_AES_GCM_ICV16,		SADB_X_EALG_AES_GCM_ICV16	}, */
	{END_OF_LIST,				0							},
};

/**
 * Algorithms for integrity protection
 */
static kernel_algorithm_t integrity_algs[] = {
	{AUTH_HMAC_MD5_96,			SADB_AALG_MD5HMAC			},
	{AUTH_HMAC_SHA1_96,			SADB_AALG_SHA1HMAC			},
	{AUTH_HMAC_SHA2_256_128,	SADB_X_AALG_SHA2_256HMAC	},
	{AUTH_HMAC_SHA2_384_192,	SADB_X_AALG_SHA2_384HMAC	},
	{AUTH_HMAC_SHA2_512_256,	SADB_X_AALG_SHA2_512HMAC	},
/*	{AUTH_DES_MAC,				0,							}, */
/*	{AUTH_KPDK_MD5,				0,							}, */
#ifdef SADB_X_AALG_AES_XCBC_MAC
	{AUTH_AES_XCBC_96,			SADB_X_AALG_AES_XCBC_MAC,	},
#endif
	{END_OF_LIST,				0,							},
};

#if 0
/**
 * Algorithms for IPComp, unused yet
 */
static kernel_algorithm_t compression_algs[] = {
/*	{IPCOMP_OUI,				0							}, */
	{IPCOMP_DEFLATE,			SADB_X_CALG_DEFLATE			},
	{IPCOMP_LZS,				SADB_X_CALG_LZS				},
	{IPCOMP_LZJH,				SADB_X_CALG_LZJH			},
	{END_OF_LIST,				0							},
};
#endif

/**
 * Look up a kernel algorithm ID and its key size
 */
static int lookup_algorithm(kernel_algorithm_t *list, int ikev2)
{
	while (list->ikev2 != END_OF_LIST)
	{
		if (ikev2 == list->ikev2)
		{
			return list->kernel;
		}
		list++;
	}
	return 0;
}

/**
 * add a host behind a sadb_address extension
 */
static void host2ext(host_t *host, struct sadb_address *ext)
{
	sockaddr_t *host_addr = host->get_sockaddr(host);
	socklen_t *len = host->get_sockaddr_len(host);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	host_addr->sa_len = *len;
#endif
	memcpy((char*)(ext + 1), host_addr, *len);
	ext->sadb_address_len = PFKEY_LEN(sizeof(*ext) + *len);
}

/**
 * add a host to the given sadb_msg
 */
static void add_addr_ext(struct sadb_msg *msg, host_t *host, u_int16_t type,
						 u_int8_t proto, u_int8_t prefixlen)
{
	struct sadb_address *addr = (struct sadb_address*)PFKEY_EXT_ADD_NEXT(msg);
	addr->sadb_address_exttype = type;
	addr->sadb_address_proto = proto;
	addr->sadb_address_prefixlen = prefixlen;
	host2ext(host, addr);
	PFKEY_EXT_ADD(msg, addr);
}

/**
 * adds an empty address extension to the given sadb_msg
 */
static void add_anyaddr_ext(struct sadb_msg *msg, int family, u_int8_t type)
{
	socklen_t len = (family == AF_INET) ? sizeof(struct sockaddr_in) :
										  sizeof(struct sockaddr_in6);
	struct sadb_address *addr = (struct sadb_address*)PFKEY_EXT_ADD_NEXT(msg);
	addr->sadb_address_exttype = type;
	sockaddr_t *saddr = (sockaddr_t*)(addr + 1);
	saddr->sa_family = family;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	saddr->sa_len = len;
#endif
	addr->sadb_address_len = PFKEY_LEN(sizeof(*addr) + len);
	PFKEY_EXT_ADD(msg, addr);
}

#ifdef HAVE_NATT
/**
 * add udp encap extensions to a sadb_msg
 */
static void add_encap_ext(struct sadb_msg *msg, host_t *src, host_t *dst)
{
	struct sadb_x_nat_t_type* nat_type;
	struct sadb_x_nat_t_port* nat_port;

	nat_type = (struct sadb_x_nat_t_type*)PFKEY_EXT_ADD_NEXT(msg);
	nat_type->sadb_x_nat_t_type_exttype = SADB_X_EXT_NAT_T_TYPE;
	nat_type->sadb_x_nat_t_type_len = PFKEY_LEN(sizeof(struct sadb_x_nat_t_type));
	nat_type->sadb_x_nat_t_type_type = UDP_ENCAP_ESPINUDP;
	PFKEY_EXT_ADD(msg, nat_type);

	nat_port = (struct sadb_x_nat_t_port*)PFKEY_EXT_ADD_NEXT(msg);
	nat_port->sadb_x_nat_t_port_exttype = SADB_X_EXT_NAT_T_SPORT;
	nat_port->sadb_x_nat_t_port_len = PFKEY_LEN(sizeof(struct sadb_x_nat_t_port));
	nat_port->sadb_x_nat_t_port_port = htons(src->get_port(src));
	PFKEY_EXT_ADD(msg, nat_port);

	nat_port = (struct sadb_x_nat_t_port*)PFKEY_EXT_ADD_NEXT(msg);
	nat_port->sadb_x_nat_t_port_exttype = SADB_X_EXT_NAT_T_DPORT;
	nat_port->sadb_x_nat_t_port_len = PFKEY_LEN(sizeof(struct sadb_x_nat_t_port));
	nat_port->sadb_x_nat_t_port_port = htons(dst->get_port(dst));
	PFKEY_EXT_ADD(msg, nat_port);
}
#endif /*HAVE_NATT*/

/**
 * Convert a sadb_address to a traffic_selector
 */
static traffic_selector_t* sadb_address2ts(struct sadb_address *address)
{
	traffic_selector_t *ts;
	host_t *host;

	/* The Linux 2.6 kernel does not set the protocol and port information
	 * in the src and dst sadb_address extensions of the SADB_ACQUIRE message.
	 */
	host = host_create_from_sockaddr((sockaddr_t*)&address[1])	;
	ts = traffic_selector_create_from_subnet(host, address->sadb_address_prefixlen,
				address->sadb_address_proto, host->get_port(host));
	return ts;
}

/**
 * Parses a pfkey message received from the kernel
 */
static status_t parse_pfkey_message(struct sadb_msg *msg, pfkey_msg_t *out)
{
	struct sadb_ext* ext;
	size_t len;

	memset(out, 0, sizeof(pfkey_msg_t));
	out->msg = msg;

	len = msg->sadb_msg_len;
	len -= PFKEY_LEN(sizeof(struct sadb_msg));

	ext = (struct sadb_ext*)(((char*)msg) + sizeof(struct sadb_msg));

	while (len >= PFKEY_LEN(sizeof(struct sadb_ext)))
	{
		DBG3(DBG_KNL, "  %N", sadb_ext_type_names, ext->sadb_ext_type);
		if (ext->sadb_ext_len < PFKEY_LEN(sizeof(struct sadb_ext)) ||
			ext->sadb_ext_len > len)
		{
			DBG1(DBG_KNL, "length of %N extension is invalid",
						   sadb_ext_type_names, ext->sadb_ext_type);
			break;
		}

		if ((ext->sadb_ext_type > SADB_EXT_MAX) || (!ext->sadb_ext_type))
		{
			DBG1(DBG_KNL, "type of PF_KEY extension (%d) is invalid", ext->sadb_ext_type);
			break;
		}

		if (out->ext[ext->sadb_ext_type])
		{
			DBG1(DBG_KNL, "duplicate %N extension",
						   sadb_ext_type_names, ext->sadb_ext_type);
			break;
		}

		out->ext[ext->sadb_ext_type] = ext;
		ext = PFKEY_EXT_NEXT_LEN(ext, len);
	}

	if (len)
	{
		DBG1(DBG_KNL, "PF_KEY message length is invalid");
		return FAILED;
	}

	return SUCCESS;
}

/**
 * Send a message to a specific PF_KEY socket and handle the response.
 */
static status_t pfkey_send_socket(private_kernel_pfkey_ipsec_t *this, int socket,
					struct sadb_msg *in, struct sadb_msg **out, size_t *out_len)
{
	unsigned char buf[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg;
	int in_len, len;

	this->mutex_pfkey->lock(this->mutex_pfkey);

	/* FIXME: our usage of sequence numbers is probably wrong. check RFC 2367,
	 * in particular the behavior in response to an SADB_ACQUIRE. */
	in->sadb_msg_seq = ++this->seq;
	in->sadb_msg_pid = getpid();

	in_len = PFKEY_USER_LEN(in->sadb_msg_len);

	while (TRUE)
	{
		len = send(socket, in, in_len, 0);

		if (len != in_len)
		{
			if (errno == EINTR)
			{
				/* interrupted, try again */
				continue;
			}
			this->mutex_pfkey->unlock(this->mutex_pfkey);
			DBG1(DBG_KNL, "error sending to PF_KEY socket: %s", strerror(errno));
			return FAILED;
		}
		break;
	}

	while (TRUE)
	{
		msg = (struct sadb_msg*)buf;

		len = recv(socket, buf, sizeof(buf), 0);

		if (len < 0)
		{
			if (errno == EINTR)
			{
				DBG1(DBG_KNL, "got interrupted");
				/* interrupted, try again */
				continue;
			}
			DBG1(DBG_KNL, "error reading from PF_KEY socket: %s", strerror(errno));
			this->mutex_pfkey->unlock(this->mutex_pfkey);
			return FAILED;
		}
		if (len < sizeof(struct sadb_msg) ||
			msg->sadb_msg_len < PFKEY_LEN(sizeof(struct sadb_msg)))
		{
			DBG1(DBG_KNL, "received corrupted PF_KEY message");
			this->mutex_pfkey->unlock(this->mutex_pfkey);
			return FAILED;
		}
		if (msg->sadb_msg_len > len / PFKEY_ALIGNMENT)
		{
			DBG1(DBG_KNL, "buffer was too small to receive the complete PF_KEY message");
			this->mutex_pfkey->unlock(this->mutex_pfkey);
			return FAILED;
		}
		if (msg->sadb_msg_pid != in->sadb_msg_pid)
		{
			DBG2(DBG_KNL, "received PF_KEY message is not intended for us");
			continue;
		}
		if (msg->sadb_msg_seq != this->seq)
		{
			DBG1(DBG_KNL, "received PF_KEY message with unexpected sequence "
				 "number, was %d expected %d", msg->sadb_msg_seq, this->seq);
			if (msg->sadb_msg_seq == 0)
			{
				/* FreeBSD and Mac OS X do this for the response to
				 * SADB_X_SPDGET (but not for the response to SADB_GET).
				 * FreeBSD: 'key_spdget' in /usr/src/sys/netipsec/key.c. */
			}
			else if (msg->sadb_msg_seq < this->seq)
			{
				continue;
			}
			else
			{
				this->mutex_pfkey->unlock(this->mutex_pfkey);
				return FAILED;
			}
		}
		if (msg->sadb_msg_type != in->sadb_msg_type)
		{
			DBG2(DBG_KNL, "received PF_KEY message of wrong type, "
					"was %d expected %d, ignoring",
					msg->sadb_msg_type, in->sadb_msg_type);
		}
		break;
	}

	*out_len = len;
	*out = (struct sadb_msg*)malloc(len);
	memcpy(*out, buf, len);

	this->mutex_pfkey->unlock(this->mutex_pfkey);

	return SUCCESS;
}

/**
 * Send a message to the default PF_KEY socket and handle the response.
 */
static status_t pfkey_send(private_kernel_pfkey_ipsec_t *this,
					struct sadb_msg *in, struct sadb_msg **out, size_t *out_len)
{
	return pfkey_send_socket(this, this->socket, in, out, out_len);
}

/**
 * Process a SADB_ACQUIRE message from the kernel
 */
static void process_acquire(private_kernel_pfkey_ipsec_t *this, struct sadb_msg* msg)
{
	pfkey_msg_t response;
	u_int32_t index, reqid = 0;
	traffic_selector_t *src_ts, *dst_ts;
	policy_entry_t *policy;
	job_t *job;

	switch (msg->sadb_msg_satype)
	{
		case SADB_SATYPE_UNSPEC:
		case SADB_SATYPE_ESP:
		case SADB_SATYPE_AH:
			break;
		default:
			/* acquire for AH/ESP only */
			return;
	}
	DBG2(DBG_KNL, "received an SADB_ACQUIRE");

	if (parse_pfkey_message(msg, &response) != SUCCESS)
	{
		DBG1(DBG_KNL, "parsing SADB_ACQUIRE from kernel failed");
		return;
	}

	index = response.x_policy->sadb_x_policy_id;
	this->mutex->lock(this->mutex);
	if (this->policies->find_first(this->policies,
			(linked_list_match_t)policy_entry_match_byindex, (void**)&policy, &index) == SUCCESS)
	{
		reqid = policy->reqid;
	}
	else
	{
		DBG1(DBG_KNL, "received an SADB_ACQUIRE with policy id %d but no matching policy found",
					   index);
	}
	src_ts = sadb_address2ts(response.src);
	dst_ts = sadb_address2ts(response.dst);
	this->mutex->unlock(this->mutex);

	DBG1(DBG_KNL, "creating acquire job for policy %R === %R with reqid {%u}",
				   src_ts, dst_ts, reqid);
	job = (job_t*)acquire_job_create(reqid, src_ts, dst_ts);
	charon->processor->queue_job(charon->processor, job);
}

/**
 * Process a SADB_EXPIRE message from the kernel
 */
static void process_expire(private_kernel_pfkey_ipsec_t *this, struct sadb_msg* msg)
{
	pfkey_msg_t response;
	protocol_id_t protocol;
	u_int32_t spi, reqid;
	bool hard;
	job_t *job;

	DBG2(DBG_KNL, "received an SADB_EXPIRE");

	if (parse_pfkey_message(msg, &response) != SUCCESS)
	{
		DBG1(DBG_KNL, "parsing SADB_EXPIRE from kernel failed");
		return;
	}

	protocol = proto_satype2ike(msg->sadb_msg_satype);
	spi = response.sa->sadb_sa_spi;
	reqid = response.x_sa2->sadb_x_sa2_reqid;
	hard = response.lft_hard != NULL;

	if (protocol != PROTO_ESP && protocol != PROTO_AH)
	{
		DBG2(DBG_KNL, "ignoring SADB_EXPIRE for SA with SPI %.8x and reqid {%u} "
					  "which is not a CHILD_SA", ntohl(spi), reqid);
		return;
	}

	DBG1(DBG_KNL, "creating %s job for %N CHILD_SA with SPI %.8x and reqid {%u}",
		 hard ? "delete" : "rekey",  protocol_id_names,
		 protocol, ntohl(spi), reqid);
	if (hard)
	{
		job = (job_t*)delete_child_sa_job_create(reqid, protocol, spi);
	}
	else
	{
		job = (job_t*)rekey_child_sa_job_create(reqid, protocol, spi);
	}
	charon->processor->queue_job(charon->processor, job);
}

#ifdef SADB_X_MIGRATE
/**
 * Process a SADB_X_MIGRATE message from the kernel
 */
static void process_migrate(private_kernel_pfkey_ipsec_t *this, struct sadb_msg* msg)
{
	pfkey_msg_t response;
	traffic_selector_t *src_ts, *dst_ts;
	policy_dir_t dir;
	u_int32_t reqid = 0;
	host_t *local = NULL, *remote = NULL;
	job_t *job;

	DBG2(DBG_KNL, "received an SADB_X_MIGRATE");

	if (parse_pfkey_message(msg, &response) != SUCCESS)
	{
		DBG1(DBG_KNL, "parsing SADB_X_MIGRATE from kernel failed");
		return;
	}
	src_ts = sadb_address2ts(response.src);
	dst_ts = sadb_address2ts(response.dst);
	dir = kernel2dir(response.x_policy->sadb_x_policy_dir);
	DBG2(DBG_KNL, "  policy %R === %R %N, id %u", src_ts, dst_ts,
					 policy_dir_names, dir);

	/* SADB_X_EXT_KMADDRESS is not present in unpatched kernels < 2.6.28 */
	if (response.x_kmaddress)
	{
		sockaddr_t *local_addr, *remote_addr;
		u_int32_t local_len;

		local_addr  = (sockaddr_t*)&response.x_kmaddress[1];
		local = host_create_from_sockaddr(local_addr);
		local_len = (local_addr->sa_family == AF_INET6)?
					sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
		remote_addr = (sockaddr_t*)((u_int8_t*)local_addr + local_len);
		remote = host_create_from_sockaddr(remote_addr);
		DBG2(DBG_KNL, "  kmaddress: %H...%H", local, remote);
	}

	if (src_ts && dst_ts && local && remote)
	{
		DBG1(DBG_KNL, "creating migrate job for policy %R === %R %N with reqid {%u}",
					   src_ts, dst_ts, policy_dir_names, dir, reqid, local);
		job = (job_t*)migrate_job_create(reqid, src_ts, dst_ts, dir,
										 local, remote);
		charon->processor->queue_job(charon->processor, job);
	}
	else
	{
		DESTROY_IF(src_ts);
		DESTROY_IF(dst_ts);
		DESTROY_IF(local);
		DESTROY_IF(remote);
	}
}
#endif /*SADB_X_MIGRATE*/

#ifdef HAVE_NATT
/**
 * Process a SADB_X_NAT_T_NEW_MAPPING message from the kernel
 */
static void process_mapping(private_kernel_pfkey_ipsec_t *this, struct sadb_msg* msg)
{
	pfkey_msg_t response;
	u_int32_t spi, reqid;
	host_t *host;
	job_t *job;

	DBG2(DBG_KNL, "received an SADB_X_NAT_T_NEW_MAPPING");

	if (parse_pfkey_message(msg, &response) != SUCCESS)
	{
		DBG1(DBG_KNL, "parsing SADB_X_NAT_T_NEW_MAPPING from kernel failed");
		return;
	}

	if (!response.x_sa2)
	{
		DBG1(DBG_KNL, "received SADB_X_NAT_T_NEW_MAPPING is missing required information");
		return;
	}

	spi = response.sa->sadb_sa_spi;
	reqid = response.x_sa2->sadb_x_sa2_reqid;

	if (proto_satype2ike(msg->sadb_msg_satype) == PROTO_ESP)
	{
		sockaddr_t *sa = (sockaddr_t*)(response.dst + 1);
		switch (sa->sa_family)
		{
			case AF_INET:
			{
				struct sockaddr_in *sin = (struct sockaddr_in*)sa;
				sin->sin_port = htons(response.x_natt_dport->sadb_x_nat_t_port_port);
			}
			case AF_INET6:
			{
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
				sin6->sin6_port = htons(response.x_natt_dport->sadb_x_nat_t_port_port);
			}
			default:
				break;
		}
		host = host_create_from_sockaddr(sa);
		if (host)
		{
			DBG1(DBG_KNL, "NAT mappings of ESP CHILD_SA with SPI %.8x and "
				"reqid {%u} changed, queuing update job", ntohl(spi), reqid);
			job = (job_t*)update_sa_job_create(reqid, host);
			charon->processor->queue_job(charon->processor, job);
		}
	}
}
#endif /*HAVE_NATT*/

/**
 * Receives events from kernel
 */
static job_requeue_t receive_events(private_kernel_pfkey_ipsec_t *this)
{
	unsigned char buf[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg = (struct sadb_msg*)buf;
	int len;
	bool oldstate;

	oldstate = thread_cancelability(TRUE);
	len = recvfrom(this->socket_events, buf, sizeof(buf), 0, NULL, 0);
	thread_cancelability(oldstate);

	if (len < 0)
	{
		switch (errno)
		{
			case EINTR:
				/* interrupted, try again */
				return JOB_REQUEUE_DIRECT;
			case EAGAIN:
				/* no data ready, select again */
				return JOB_REQUEUE_DIRECT;
			default:
				DBG1(DBG_KNL, "unable to receive from PF_KEY event socket");
				sleep(1);
				return JOB_REQUEUE_FAIR;
		}
	}

	if (len < sizeof(struct sadb_msg) ||
		msg->sadb_msg_len < PFKEY_LEN(sizeof(struct sadb_msg)))
	{
		DBG2(DBG_KNL, "received corrupted PF_KEY message");
		return JOB_REQUEUE_DIRECT;
	}
	if (msg->sadb_msg_pid != 0)
	{	/* not from kernel. not interested, try another one */
		return JOB_REQUEUE_DIRECT;
	}
	if (msg->sadb_msg_len > len / PFKEY_ALIGNMENT)
	{
		DBG1(DBG_KNL, "buffer was too small to receive the complete PF_KEY message");
		return JOB_REQUEUE_DIRECT;
	}

	switch (msg->sadb_msg_type)
	{
		case SADB_ACQUIRE:
			process_acquire(this, msg);
			break;
		case SADB_EXPIRE:
			process_expire(this, msg);
			break;
#ifdef SADB_X_MIGRATE
		case SADB_X_MIGRATE:
			process_migrate(this, msg);
			break;
#endif /*SADB_X_MIGRATE*/
#ifdef HAVE_NATT
		case SADB_X_NAT_T_NEW_MAPPING:
			process_mapping(this, msg);
			break;
#endif /*HAVE_NATT*/
		default:
			break;
	}

	return JOB_REQUEUE_DIRECT;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_pfkey_ipsec_t *this, host_t *src, host_t *dst,
	protocol_id_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	unsigned char request[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg, *out;
	struct sadb_x_sa2 *sa2;
	struct sadb_spirange *range;
	pfkey_msg_t response;
	u_int32_t received_spi = 0;
	size_t len;

	memset(&request, 0, sizeof(request));

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_GETSPI;
	msg->sadb_msg_satype = proto_ike2satype(protocol);
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

	sa2 = (struct sadb_x_sa2*)PFKEY_EXT_ADD_NEXT(msg);
	sa2->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	sa2->sadb_x_sa2_len = PFKEY_LEN(sizeof(struct sadb_spirange));
	sa2->sadb_x_sa2_reqid = reqid;
	PFKEY_EXT_ADD(msg, sa2);

	add_addr_ext(msg, src, SADB_EXT_ADDRESS_SRC, 0, 0);
	add_addr_ext(msg, dst, SADB_EXT_ADDRESS_DST, 0, 0);

	range = (struct sadb_spirange*)PFKEY_EXT_ADD_NEXT(msg);
	range->sadb_spirange_exttype = SADB_EXT_SPIRANGE;
	range->sadb_spirange_len = PFKEY_LEN(sizeof(struct sadb_spirange));
	range->sadb_spirange_min = 0xc0000000;
	range->sadb_spirange_max = 0xcFFFFFFF;
	PFKEY_EXT_ADD(msg, range);

	if (pfkey_send(this, msg, &out, &len) == SUCCESS)
	{
		if (out->sadb_msg_errno)
		{
			DBG1(DBG_KNL, "allocating SPI failed: %s (%d)",
					strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		}
		else if (parse_pfkey_message(out, &response) == SUCCESS)
		{
			received_spi = response.sa->sadb_sa_spi;
		}
		free(out);
	}

	if (received_spi == 0)
	{
		return FAILED;
	}

	*spi = received_spi;
	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_pfkey_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t reqid, u_int16_t *cpi)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_pfkey_ipsec_t *this, host_t *src, host_t *dst, u_int32_t spi,
	protocol_id_t protocol, u_int32_t reqid, lifetime_cfg_t *lifetime,
	u_int16_t enc_alg, chunk_t enc_key, u_int16_t int_alg, chunk_t int_key,
	ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi, bool encap,
	bool inbound, traffic_selector_t *src_ts, traffic_selector_t *dst_ts)
{
	unsigned char request[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg, *out;
	struct sadb_sa *sa;
	struct sadb_x_sa2 *sa2;
	struct sadb_lifetime *lft;
	struct sadb_key *key;
	size_t len;

	memset(&request, 0, sizeof(request));

	DBG2(DBG_KNL, "adding SAD entry with SPI %.8x and reqid {%u}", ntohl(spi), reqid);

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = inbound ? SADB_UPDATE : SADB_ADD;
	msg->sadb_msg_satype = proto_ike2satype(protocol);
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

#ifdef __APPLE__
	if (encap)
	{
		struct sadb_sa_2 *sa_2;
		sa_2 = (struct sadb_sa_2*)PFKEY_EXT_ADD_NEXT(msg);
		sa_2->sadb_sa_natt_port = dst->get_port(dst);
		sa = &sa_2->sa;
		sa->sadb_sa_flags |= SADB_X_EXT_NATT;
		len = sizeof(struct sadb_sa_2);
	}
	else
#endif
	{
		sa = (struct sadb_sa*)PFKEY_EXT_ADD_NEXT(msg);
		len = sizeof(struct sadb_sa);
	}
	sa->sadb_sa_exttype = SADB_EXT_SA;
	sa->sadb_sa_len = PFKEY_LEN(len);
	sa->sadb_sa_spi = spi;
	sa->sadb_sa_replay = (protocol == IPPROTO_COMP) ? 0 : 32;
	sa->sadb_sa_auth = lookup_algorithm(integrity_algs, int_alg);
	sa->sadb_sa_encrypt = lookup_algorithm(encryption_algs, enc_alg);
	PFKEY_EXT_ADD(msg, sa);

	sa2 = (struct sadb_x_sa2*)PFKEY_EXT_ADD_NEXT(msg);
	sa2->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	sa2->sadb_x_sa2_len = PFKEY_LEN(sizeof(struct sadb_spirange));
	sa2->sadb_x_sa2_mode = mode2kernel(mode);
	sa2->sadb_x_sa2_reqid = reqid;
	PFKEY_EXT_ADD(msg, sa2);

	add_addr_ext(msg, src, SADB_EXT_ADDRESS_SRC, 0, 0);
	add_addr_ext(msg, dst, SADB_EXT_ADDRESS_DST, 0, 0);

	lft = (struct sadb_lifetime*)PFKEY_EXT_ADD_NEXT(msg);
	lft->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
	lft->sadb_lifetime_len = PFKEY_LEN(sizeof(struct sadb_lifetime));
	lft->sadb_lifetime_allocations = lifetime->packets.rekey;
	lft->sadb_lifetime_bytes = lifetime->bytes.rekey;
	lft->sadb_lifetime_addtime = lifetime->time.rekey;
	lft->sadb_lifetime_usetime = 0; /* we only use addtime */
	PFKEY_EXT_ADD(msg, lft);

	lft = (struct sadb_lifetime*)PFKEY_EXT_ADD_NEXT(msg);
	lft->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
	lft->sadb_lifetime_len = PFKEY_LEN(sizeof(struct sadb_lifetime));
	lft->sadb_lifetime_allocations = lifetime->packets.life;
	lft->sadb_lifetime_bytes = lifetime->bytes.life;
	lft->sadb_lifetime_addtime = lifetime->time.life;
	lft->sadb_lifetime_usetime = 0; /* we only use addtime */
	PFKEY_EXT_ADD(msg, lft);

	if (enc_alg != ENCR_UNDEFINED)
	{
		if (!sa->sadb_sa_encrypt)
		{
			DBG1(DBG_KNL, "algorithm %N not supported by kernel!",
				 encryption_algorithm_names, enc_alg);
			return FAILED;
		}
		DBG2(DBG_KNL, "  using encryption algorithm %N with key size %d",
			 encryption_algorithm_names, enc_alg, enc_key.len * 8);

		key = (struct sadb_key*)PFKEY_EXT_ADD_NEXT(msg);
		key->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
		key->sadb_key_bits = enc_key.len * 8;
		key->sadb_key_len = PFKEY_LEN(sizeof(struct sadb_key) + enc_key.len);
		memcpy(key + 1, enc_key.ptr, enc_key.len);

		PFKEY_EXT_ADD(msg, key);
	}

	if (int_alg != AUTH_UNDEFINED)
	{
		if (!sa->sadb_sa_auth)
		{
			DBG1(DBG_KNL, "algorithm %N not supported by kernel!",
					 integrity_algorithm_names, int_alg);
			return FAILED;
		}
		DBG2(DBG_KNL, "  using integrity algorithm %N with key size %d",
			 integrity_algorithm_names, int_alg, int_key.len * 8);

		key = (struct sadb_key*)PFKEY_EXT_ADD_NEXT(msg);
		key->sadb_key_exttype = SADB_EXT_KEY_AUTH;
		key->sadb_key_bits = int_key.len * 8;
		key->sadb_key_len = PFKEY_LEN(sizeof(struct sadb_key) + int_key.len);
		memcpy(key + 1, int_key.ptr, int_key.len);

		PFKEY_EXT_ADD(msg, key);
	}

	if (ipcomp != IPCOMP_NONE)
	{
		/*TODO*/
	}

#ifdef HAVE_NATT
	if (encap)
	{
		add_encap_ext(msg, src, dst);
	}
#endif /*HAVE_NATT*/

	if (pfkey_send(this, msg, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to add SAD entry with SPI %.8x", ntohl(spi));
		return FAILED;
	}
	else if (out->sadb_msg_errno)
	{
		DBG1(DBG_KNL, "unable to add SAD entry with SPI %.8x: %s (%d)",
				ntohl(spi), strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		free(out);
		return FAILED;
	}

	free(out);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_pfkey_ipsec_t *this, u_int32_t spi, protocol_id_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool encap, bool new_encap)
{
	unsigned char request[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg, *out;
	struct sadb_sa *sa;
	pfkey_msg_t response;
	size_t len;

	/* we can't update the SA if any of the ip addresses have changed.
	 * that's because we can't use SADB_UPDATE and by deleting and readding the
	 * SA the sequence numbers would get lost */
	if (!src->ip_equals(src, new_src) ||
		!dst->ip_equals(dst, new_dst))
	{
		DBG1(DBG_KNL, "unable to update SAD entry with SPI %.8x: address changes"
				" are not supported", ntohl(spi));
		return NOT_SUPPORTED;
	}

	memset(&request, 0, sizeof(request));

	DBG2(DBG_KNL, "querying SAD entry with SPI %.8x", ntohl(spi));

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_GET;
	msg->sadb_msg_satype = proto_ike2satype(protocol);
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

	sa = (struct sadb_sa*)PFKEY_EXT_ADD_NEXT(msg);
	sa->sadb_sa_exttype = SADB_EXT_SA;
	sa->sadb_sa_len = PFKEY_LEN(sizeof(struct sadb_sa));
	sa->sadb_sa_spi = spi;
	PFKEY_EXT_ADD(msg, sa);

	/* the kernel wants a SADB_EXT_ADDRESS_SRC to be present even though
	 * it is not used for anything. */
	add_anyaddr_ext(msg, dst->get_family(dst), SADB_EXT_ADDRESS_SRC);
	add_addr_ext(msg, dst, SADB_EXT_ADDRESS_DST, 0, 0);

	if (pfkey_send(this, msg, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to query SAD entry with SPI %.8x",
				ntohl(spi));
		return FAILED;
	}
	else if (out->sadb_msg_errno)
	{
		DBG1(DBG_KNL, "unable to query SAD entry with SPI %.8x: %s (%d)",
			ntohl(spi), strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		free(out);
		return FAILED;
	}
	else if (parse_pfkey_message(out, &response) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to query SAD entry with SPI %.8x: parsing response "
				"from kernel failed", ntohl(spi));
		free(out);
		return FAILED;
	}

	DBG2(DBG_KNL, "updating SAD entry with SPI %.8x from %#H..%#H to %#H..%#H",
		 ntohl(spi), src, dst, new_src, new_dst);

	memset(&request, 0, sizeof(request));

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_UPDATE;
	msg->sadb_msg_satype = proto_ike2satype(protocol);
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

#ifdef __APPLE__
	{
		struct sadb_sa_2 *sa_2;
		sa_2 = (struct sadb_sa_2*)PFKEY_EXT_ADD_NEXT(msg);
		sa_2->sa.sadb_sa_len = PFKEY_LEN(sizeof(struct sadb_sa_2));
		memcpy(&sa_2->sa, response.sa, sizeof(struct sadb_sa));
		if (encap)
		{
			sa_2->sadb_sa_natt_port = new_dst->get_port(new_dst);
			sa_2->sa.sadb_sa_flags |= SADB_X_EXT_NATT;
		}
	}
#else
	PFKEY_EXT_COPY(msg, response.sa);
#endif
	PFKEY_EXT_COPY(msg, response.x_sa2);

	PFKEY_EXT_COPY(msg, response.src);
	PFKEY_EXT_COPY(msg, response.dst);

	PFKEY_EXT_COPY(msg, response.lft_soft);
	PFKEY_EXT_COPY(msg, response.lft_hard);

	if (response.key_encr)
	{
		PFKEY_EXT_COPY(msg, response.key_encr);
	}

	if (response.key_auth)
	{
		PFKEY_EXT_COPY(msg, response.key_auth);
	}

#ifdef HAVE_NATT
	if (new_encap)
	{
		add_encap_ext(msg, new_src, new_dst);
	}
#endif /*HAVE_NATT*/

	free(out);

	if (pfkey_send(this, msg, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to update SAD entry with SPI %.8x", ntohl(spi));
		return FAILED;
	}
	else if (out->sadb_msg_errno)
	{
		DBG1(DBG_KNL, "unable to update SAD entry with SPI %.8x: %s (%d)",
				ntohl(spi), strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		free(out);
		return FAILED;
	}
	free(out);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_pfkey_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, protocol_id_t protocol, u_int64_t *bytes)
{
	unsigned char request[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg, *out;
	struct sadb_sa *sa;
	pfkey_msg_t response;
	size_t len;

	memset(&request, 0, sizeof(request));

	DBG2(DBG_KNL, "querying SAD entry with SPI %.8x", ntohl(spi));

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_GET;
	msg->sadb_msg_satype = proto_ike2satype(protocol);
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

	sa = (struct sadb_sa*)PFKEY_EXT_ADD_NEXT(msg);
	sa->sadb_sa_exttype = SADB_EXT_SA;
	sa->sadb_sa_len = PFKEY_LEN(sizeof(struct sadb_sa));
	sa->sadb_sa_spi = spi;
	PFKEY_EXT_ADD(msg, sa);

	/* the Linux Kernel doesn't care for the src address, but other systems do
	 * (e.g. FreeBSD)
	 */
	add_addr_ext(msg, src, SADB_EXT_ADDRESS_SRC, 0, 0);
	add_addr_ext(msg, dst, SADB_EXT_ADDRESS_DST, 0, 0);

	if (pfkey_send(this, msg, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to query SAD entry with SPI %.8x", ntohl(spi));
		return FAILED;
	}
	else if (out->sadb_msg_errno)
	{
		DBG1(DBG_KNL, "unable to query SAD entry with SPI %.8x: %s (%d)",
				ntohl(spi), strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		free(out);
		return FAILED;
	}
	else if (parse_pfkey_message(out, &response) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to query SAD entry with SPI %.8x", ntohl(spi));
		free(out);
		return FAILED;
	}
	*bytes = response.lft_current->sadb_lifetime_bytes;

	free(out);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_pfkey_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, protocol_id_t protocol, u_int16_t cpi)
{
	unsigned char request[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg, *out;
	struct sadb_sa *sa;
	size_t len;

	memset(&request, 0, sizeof(request));

	DBG2(DBG_KNL, "deleting SAD entry with SPI %.8x", ntohl(spi));

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_DELETE;
	msg->sadb_msg_satype = proto_ike2satype(protocol);
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

	sa = (struct sadb_sa*)PFKEY_EXT_ADD_NEXT(msg);
	sa->sadb_sa_exttype = SADB_EXT_SA;
	sa->sadb_sa_len = PFKEY_LEN(sizeof(struct sadb_sa));
	sa->sadb_sa_spi = spi;
	PFKEY_EXT_ADD(msg, sa);

	/* the Linux Kernel doesn't care for the src address, but other systems do
	 * (e.g. FreeBSD)
	 */
	add_addr_ext(msg, src, SADB_EXT_ADDRESS_SRC, 0, 0);
	add_addr_ext(msg, dst, SADB_EXT_ADDRESS_DST, 0, 0);

	if (pfkey_send(this, msg, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to delete SAD entry with SPI %.8x", ntohl(spi));
		return FAILED;
	}
	else if (out->sadb_msg_errno)
	{
		DBG1(DBG_KNL, "unable to delete SAD entry with SPI %.8x: %s (%d)",
				ntohl(spi), strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		free(out);
		return FAILED;
	}

	DBG2(DBG_KNL, "deleted SAD entry with SPI %.8x", ntohl(spi));
	free(out);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_pfkey_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, u_int32_t spi, protocol_id_t protocol,
	u_int32_t reqid, ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi,
	bool routed)
{
	unsigned char request[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg, *out;
	struct sadb_x_policy *pol;
	struct sadb_x_ipsecrequest *req;
	policy_entry_t *policy, *found = NULL;
	pfkey_msg_t response;
	size_t len;

	if (dir2kernel(direction) == IPSEC_DIR_INVALID)
	{
		/* FWD policies are not supported on all platforms */
		return SUCCESS;
	}

	/* create a policy */
	policy = create_policy_entry(src_ts, dst_ts, direction, reqid);

	/* find a matching policy */
	this->mutex->lock(this->mutex);
	if (this->policies->find_first(this->policies,
			(linked_list_match_t)policy_entry_equals, (void**)&found, policy) == SUCCESS)
	{
		/* use existing policy */
		found->refcount++;
		DBG2(DBG_KNL, "policy %R === %R %N already exists, increasing "
					  "refcount", src_ts, dst_ts,
					   policy_dir_names, direction);
		policy_entry_destroy(policy);
		policy = found;
	}
	else
	{
		/* apply the new one, if we have no such policy */
		this->policies->insert_last(this->policies, policy);
		policy->refcount = 1;
	}

	memset(&request, 0, sizeof(request));

	DBG2(DBG_KNL, "adding policy %R === %R %N", src_ts, dst_ts,
				   policy_dir_names, direction);

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = found ? SADB_X_SPDUPDATE : SADB_X_SPDADD;
	msg->sadb_msg_satype = 0;
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

	pol = (struct sadb_x_policy*)PFKEY_EXT_ADD_NEXT(msg);
	pol->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	pol->sadb_x_policy_len = PFKEY_LEN(sizeof(struct sadb_x_policy));
	pol->sadb_x_policy_id = 0;
	pol->sadb_x_policy_dir = dir2kernel(direction);
	pol->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
#ifdef HAVE_STRUCT_SADB_X_POLICY_SADB_X_POLICY_PRIORITY
	/* calculate priority based on source selector size, small size = high prio */
	pol->sadb_x_policy_priority = routed ? PRIO_LOW : PRIO_HIGH;
	pol->sadb_x_policy_priority -= policy->src.mask * 10;
	pol->sadb_x_policy_priority -= policy->src.proto != IPSEC_PROTO_ANY ? 2 : 0;
	pol->sadb_x_policy_priority -= policy->src.net->get_port(policy->src.net) ? 1 : 0;
#endif

	/* one or more sadb_x_ipsecrequest extensions are added to the sadb_x_policy extension */
	req = (struct sadb_x_ipsecrequest*)(pol + 1);
	req->sadb_x_ipsecrequest_proto = proto_ike2ip(protocol);
	/* !!! the length of this struct MUST be in octets instead of 64 bit words */
	req->sadb_x_ipsecrequest_len = sizeof(struct sadb_x_ipsecrequest);
	req->sadb_x_ipsecrequest_mode = mode2kernel(mode);
	req->sadb_x_ipsecrequest_reqid = reqid;
	req->sadb_x_ipsecrequest_level = IPSEC_LEVEL_UNIQUE;
	if (mode == MODE_TUNNEL)
	{
		sockaddr_t *sa;
		socklen_t sl;
		sa = src->get_sockaddr(src);
		sl = *src->get_sockaddr_len(src);
		memcpy(req + 1, sa, sl);
		sa = dst->get_sockaddr(dst);
		memcpy((u_int8_t*)(req + 1) + sl, sa, sl);
		req->sadb_x_ipsecrequest_len += sl * 2;
	}

	pol->sadb_x_policy_len += PFKEY_LEN(req->sadb_x_ipsecrequest_len);
	PFKEY_EXT_ADD(msg, pol);

	add_addr_ext(msg, policy->src.net, SADB_EXT_ADDRESS_SRC, policy->src.proto,
				 policy->src.mask);
	add_addr_ext(msg, policy->dst.net, SADB_EXT_ADDRESS_DST, policy->dst.proto,
				 policy->dst.mask);

#ifdef __FreeBSD__
	{	/* on FreeBSD a lifetime has to be defined to be able to later query
		 * the current use time. */
		struct sadb_lifetime *lft;
		lft = (struct sadb_lifetime*)PFKEY_EXT_ADD_NEXT(msg);
		lft->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
		lft->sadb_lifetime_len = PFKEY_LEN(sizeof(struct sadb_lifetime));
		lft->sadb_lifetime_addtime = LONG_MAX;
		PFKEY_EXT_ADD(msg, lft);
	}
#endif

	this->mutex->unlock(this->mutex);

	if (pfkey_send(this, msg, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to add policy %R === %R %N", src_ts, dst_ts,
					   policy_dir_names, direction);
		return FAILED;
	}
	else if (out->sadb_msg_errno)
	{
		DBG1(DBG_KNL, "unable to add policy %R === %R %N: %s (%d)", src_ts, dst_ts,
					   policy_dir_names, direction,
					   strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		free(out);
		return FAILED;
	}
	else if (parse_pfkey_message(out, &response) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to add policy %R === %R %N: parsing response "
				"from kernel failed", src_ts, dst_ts, policy_dir_names, direction);
		free(out);
		return FAILED;
	}

	this->mutex->lock(this->mutex);

	/* we try to find the policy again and update the kernel index */
	if (this->policies->find_last(this->policies, NULL, (void**)&policy) != SUCCESS)
	{
		DBG2(DBG_KNL, "unable to update index, the policy %R === %R %N is "
				"already gone, ignoring", src_ts, dst_ts, policy_dir_names, direction);
		this->mutex->unlock(this->mutex);
		free(out);
		return SUCCESS;
	}
	policy->index = response.x_policy->sadb_x_policy_id;
	free(out);

	/* install a route, if:
	 * - we are NOT updating a policy
	 * - this is a forward policy (to just get one for each child)
	 * - we are in tunnel mode
	 * - we are not using IPv6 (does not work correctly yet!)
	 * - routing is not disabled via strongswan.conf
	 */
	if (policy->route == NULL && direction == POLICY_FWD &&
		mode != MODE_TRANSPORT && src->get_family(src) != AF_INET6 &&
		this->install_routes)
	{
		route_entry_t *route = malloc_thing(route_entry_t);

		if (charon->kernel_interface->get_address_by_ts(charon->kernel_interface,
				dst_ts, &route->src_ip) == SUCCESS)
		{
			/* get the nexthop to src (src as we are in POLICY_FWD).*/
			route->gateway = charon->kernel_interface->get_nexthop(
									charon->kernel_interface, src);
			route->if_name = charon->kernel_interface->get_interface(
									charon->kernel_interface, dst);
			route->dst_net = chunk_clone(policy->src.net->get_address(policy->src.net));
			route->prefixlen = policy->src.mask;

			switch (charon->kernel_interface->add_route(charon->kernel_interface,
					route->dst_net, route->prefixlen, route->gateway,
					route->src_ip, route->if_name))
			{
				default:
					DBG1(DBG_KNL, "unable to install source route for %H",
						 route->src_ip);
					/* FALL */
				case ALREADY_DONE:
					/* route exists, do not uninstall */
					route_entry_destroy(route);
					break;
				case SUCCESS:
					/* cache the installed route */
					policy->route = route;
					break;
			}
		}
		else
		{
			free(route);
		}
	}

	this->mutex->unlock(this->mutex);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_pfkey_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t *use_time)
{
	unsigned char request[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg, *out;
	struct sadb_x_policy *pol;
	policy_entry_t *policy, *found = NULL;
	pfkey_msg_t response;
	size_t len;

	if (dir2kernel(direction) == IPSEC_DIR_INVALID)
	{
		/* FWD policies are not supported on all platforms */
		return NOT_FOUND;
	}

	DBG2(DBG_KNL, "querying policy %R === %R %N", src_ts, dst_ts,
				   policy_dir_names, direction);

	/* create a policy */
	policy = create_policy_entry(src_ts, dst_ts, direction, 0);

	/* find a matching policy */
	this->mutex->lock(this->mutex);
	if (this->policies->find_first(this->policies,
			(linked_list_match_t)policy_entry_equals, (void**)&found, policy) != SUCCESS)
	{
		DBG1(DBG_KNL, "querying policy %R === %R %N failed, not found", src_ts,
					   dst_ts, policy_dir_names, direction);
		policy_entry_destroy(policy);
		this->mutex->unlock(this->mutex);
		return NOT_FOUND;
	}
	policy_entry_destroy(policy);
	policy = found;

	memset(&request, 0, sizeof(request));

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_X_SPDGET;
	msg->sadb_msg_satype = 0;
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

	pol = (struct sadb_x_policy*)PFKEY_EXT_ADD_NEXT(msg);
	pol->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	pol->sadb_x_policy_id = policy->index;
	pol->sadb_x_policy_len = PFKEY_LEN(sizeof(struct sadb_x_policy));
	pol->sadb_x_policy_dir = dir2kernel(direction);
	pol->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
	PFKEY_EXT_ADD(msg, pol);

	add_addr_ext(msg, policy->src.net, SADB_EXT_ADDRESS_SRC, policy->src.proto,
				 policy->src.mask);
	add_addr_ext(msg, policy->dst.net, SADB_EXT_ADDRESS_DST, policy->dst.proto,
				 policy->dst.mask);

	this->mutex->unlock(this->mutex);

	if (pfkey_send(this, msg, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to query policy %R === %R %N", src_ts, dst_ts,
					   policy_dir_names, direction);
		return FAILED;
	}
	else if (out->sadb_msg_errno)
	{
		DBG1(DBG_KNL, "unable to query policy %R === %R %N: %s (%d)", src_ts,
					   dst_ts, policy_dir_names, direction,
					   strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		free(out);
		return FAILED;
	}
	else if (parse_pfkey_message(out, &response) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to query policy %R === %R %N: parsing response "
				"from kernel failed", src_ts, dst_ts, policy_dir_names, direction);
		free(out);
		return FAILED;
	}
	else if (response.lft_current == NULL)
	{
		DBG1(DBG_KNL, "unable to query policy %R === %R %N: kernel reports no "
			 "use time", src_ts, dst_ts, policy_dir_names, direction);
		free(out);
		return FAILED;
	}
	/* we need the monotonic time, but the kernel returns system time. */
	if (response.lft_current->sadb_lifetime_usetime)
	{
		*use_time = time_monotonic(NULL) -
					(time(NULL) - response.lft_current->sadb_lifetime_usetime);
	}
	else
	{
		*use_time = 0;
	}
	free(out);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_pfkey_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, bool unrouted)
{
	unsigned char request[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg, *out;
	struct sadb_x_policy *pol;
	policy_entry_t *policy, *found = NULL;
	route_entry_t *route;
	size_t len;

	if (dir2kernel(direction) == IPSEC_DIR_INVALID)
	{
		/* FWD policies are not supported on all platforms */
		return SUCCESS;
	}

	DBG2(DBG_KNL, "deleting policy %R === %R %N", src_ts, dst_ts,
				   policy_dir_names, direction);

	/* create a policy */
	policy = create_policy_entry(src_ts, dst_ts, direction, 0);

	/* find a matching policy */
	this->mutex->lock(this->mutex);
	if (this->policies->find_first(this->policies,
			(linked_list_match_t)policy_entry_equals, (void**)&found, policy) == SUCCESS)
	{
		if (--found->refcount > 0)
		{
			/* is used by more SAs, keep in kernel */
			DBG2(DBG_KNL, "policy still used by another CHILD_SA, not removed");
			policy_entry_destroy(policy);
			this->mutex->unlock(this->mutex);
			return SUCCESS;
		}
		/* remove if last reference */
		this->policies->remove(this->policies, found, NULL);
		policy_entry_destroy(policy);
		policy = found;
	}
	else
	{
		DBG1(DBG_KNL, "deleting policy %R === %R %N failed, not found", src_ts,
					   dst_ts, policy_dir_names, direction);
		policy_entry_destroy(policy);
		this->mutex->unlock(this->mutex);
		return NOT_FOUND;
	}
	this->mutex->unlock(this->mutex);

	memset(&request, 0, sizeof(request));

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_X_SPDDELETE;
	msg->sadb_msg_satype = 0;
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

	pol = (struct sadb_x_policy*)PFKEY_EXT_ADD_NEXT(msg);
	pol->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	pol->sadb_x_policy_len = PFKEY_LEN(sizeof(struct sadb_x_policy));
	pol->sadb_x_policy_dir = dir2kernel(direction);
	pol->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
	PFKEY_EXT_ADD(msg, pol);

	add_addr_ext(msg, policy->src.net, SADB_EXT_ADDRESS_SRC, policy->src.proto,
				 policy->src.mask);
	add_addr_ext(msg, policy->dst.net, SADB_EXT_ADDRESS_DST, policy->dst.proto,
				 policy->dst.mask);

	route = policy->route;
	policy->route = NULL;
	policy_entry_destroy(policy);

	if (pfkey_send(this, msg, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to delete policy %R === %R %N", src_ts, dst_ts,
					   policy_dir_names, direction);
		return FAILED;
	}
	else if (out->sadb_msg_errno)
	{
		DBG1(DBG_KNL, "unable to delete policy %R === %R %N: %s (%d)", src_ts,
					   dst_ts, policy_dir_names, direction,
					   strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		free(out);
		return FAILED;
	}
	free(out);

	if (route)
	{
		if (charon->kernel_interface->del_route(charon->kernel_interface,
				route->dst_net, route->prefixlen, route->gateway,
				route->src_ip, route->if_name) != SUCCESS)
		{
			DBG1(DBG_KNL, "error uninstalling route installed with "
						  "policy %R === %R %N", src_ts, dst_ts,
						   policy_dir_names, direction);
		}
		route_entry_destroy(route);
	}

	return SUCCESS;
}

/**
 * Register a socket for AQUIRE/EXPIRE messages
 */
static status_t register_pfkey_socket(private_kernel_pfkey_ipsec_t *this,
									  u_int8_t satype)
{
	unsigned char request[PFKEY_BUFFER_SIZE];
	struct sadb_msg *msg, *out;
	size_t len;

	memset(&request, 0, sizeof(request));

	msg = (struct sadb_msg*)request;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_REGISTER;
	msg->sadb_msg_satype = satype;
	msg->sadb_msg_len = PFKEY_LEN(sizeof(struct sadb_msg));

	if (pfkey_send_socket(this, this->socket_events, msg, &out, &len) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to register PF_KEY socket");
		return FAILED;
	}
	else if (out->sadb_msg_errno)
	{
		DBG1(DBG_KNL, "unable to register PF_KEY socket: %s (%d)",
					   strerror(out->sadb_msg_errno), out->sadb_msg_errno);
		free(out);
		return FAILED;
	}
	free(out);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_pfkey_ipsec_t *this, int fd, int family)
{
	struct sadb_x_policy policy;
	u_int sol, ipsec_policy;

	switch (family)
	{
		case AF_INET:
		{
			sol = SOL_IP;
			ipsec_policy = IP_IPSEC_POLICY;
			break;
		}
		case AF_INET6:
		{
			sol = SOL_IPV6;
			ipsec_policy = IPV6_IPSEC_POLICY;
			break;
		}
		default:
			return FALSE;
	}

	memset(&policy, 0, sizeof(policy));
	policy.sadb_x_policy_len = sizeof(policy) / sizeof(u_int64_t);
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;

	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	if (setsockopt(fd, sol, ipsec_policy, &policy, sizeof(policy)) < 0)
	{
		DBG1(DBG_KNL, "unable to set IPSEC_POLICY on socket: %s",
			 strerror(errno));
		return FALSE;
	}
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	if (setsockopt(fd, sol, ipsec_policy, &policy, sizeof(policy)) < 0)
	{
		DBG1(DBG_KNL, "unable to set IPSEC_POLICY on socket: %s",
			 strerror(errno));
		return FALSE;
	}
	return TRUE;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_pfkey_ipsec_t *this)
{
	if (this->job)
	{
		this->job->cancel(this->job);
	}
	if (this->socket > 0)
	{
		close(this->socket);
	}
	if (this->socket_events > 0)
	{
		close(this->socket_events);
	}
	this->policies->destroy_function(this->policies, (void*)policy_entry_destroy);
	this->mutex->destroy(this->mutex);
	this->mutex_pfkey->destroy(this->mutex_pfkey);
	free(this);
}

/*
 * Described in header.
 */
kernel_pfkey_ipsec_t *kernel_pfkey_ipsec_create()
{
	private_kernel_pfkey_ipsec_t *this;

	INIT(this,
		.public.interface = {
			.get_spi = _get_spi,
			.get_cpi = _get_cpi,
			.add_sa  = _add_sa,
			.update_sa = _update_sa,
			.query_sa = _query_sa,
			.del_sa = _del_sa,
			.add_policy = _add_policy,
			.query_policy = _query_policy,
			.del_policy = _del_policy,
			.bypass_socket = _bypass_socket,
			.destroy = _destroy,
		},
		.policies = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.mutex_pfkey = mutex_create(MUTEX_TYPE_DEFAULT),
		.install_routes = lib->settings->get_bool(lib->settings,
												"charon.install_routes", TRUE),
	);

	/* create a PF_KEY socket to communicate with the kernel */
	this->socket = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (this->socket <= 0)
	{
		DBG1(DBG_KNL, "unable to create PF_KEY socket");
		destroy(this);
		return NULL;
	}

	/* create a PF_KEY socket for ACQUIRE & EXPIRE */
	this->socket_events = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (this->socket_events <= 0)
	{
		DBG1(DBG_KNL, "unable to create PF_KEY event socket");
		destroy(this);
		return NULL;
	}

	/* register the event socket */
	if (register_pfkey_socket(this, SADB_SATYPE_ESP) != SUCCESS ||
		register_pfkey_socket(this, SADB_SATYPE_AH) != SUCCESS)
	{
		DBG1(DBG_KNL, "unable to register PF_KEY event socket");
		destroy(this);
		return NULL;
	}

	this->job = callback_job_create((callback_job_cb_t)receive_events,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);

	return &this->public;
}

