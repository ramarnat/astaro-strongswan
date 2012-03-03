/* get-next-event loop
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifdef SOLARIS
# include <sys/sockio.h>        /* for Solaris 2.6: defines SIOCGIFCONF */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <resolv.h>
#include <arpa/nameser.h>       /* missing from <resolv.h> on old systems */
#include <sys/queue.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "connections.h"
#include "kernel.h"
#include "log.h"
#include "server.h"
#include "timer.h"
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "rcv_whack.h"
#include "keys.h"
#include "adns.h"       /* needs <resolv.h> */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "whack.h"      /* for RC_LOG_SERIOUS */

#include <pfkeyv2.h>
#include <pfkey.h>
#include "kameipsec.h"
#include "nat_traversal.h"
#include "sa_sync.h"
#include <limits.h>

/*
 *  Server main loop and socket initialization routines.
 */

static const int on = TRUE;     /* by-reference parameter; constant, we hope */

/* control (whack) socket */
int ctl_fd = NULL_FD;   /* file descriptor of control (whack) socket */
struct sockaddr_un ctl_addr = { AF_UNIX, DEFAULT_CTLBASE CTL_SUFFIX };

/* info (showpolicy) socket */
int policy_fd = NULL_FD;
struct sockaddr_un info_addr= { AF_UNIX, DEFAULT_CTLBASE INFO_SUFFIX };

/* HA System: Variables and functions for HA mode*/
char *ha_interface = NULL; /* NULL means HA System disabled, otherwise its a string with the interface name */
struct in_addr ha_mcast_addr = { INADDR_ANY };
int ha_master = -1; /* 1 TRUE is master, 0 FALSE is slave, -1 is init mode */
u_int32_t ha_seqdiff_in = SA_SYNC_SEQDIFF_IN;
u_int32_t ha_seqdiff_out = SA_SYNC_SEQDIFF_OUT;

int ha_sock = NULL_FD; /* file descriptor of ha interface socket for multicast packets */
int open_ha_iface(void);
void close_ha_iface(void);

/* Initialize the control socket.
 * Note: this is called very early, so little infrastructure is available.
 * It is important that the socket is created before the original
 * Pluto process returns.
 */
err_t
init_ctl_socket(void)
{
	err_t failed = NULL;

	delete_ctl_socket();        /* preventative medicine */
	ctl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctl_fd == -1)
		failed = "create";
	else if (fcntl(ctl_fd, F_SETFD, FD_CLOEXEC) == -1)
		failed = "fcntl FD+CLOEXEC";
	else if (setsockopt(ctl_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof(on)) < 0)
		failed = "setsockopt";
	else
	{
		/* to keep control socket secure, use umask */
		mode_t ou = umask(~S_IRWXU);

		if (bind(ctl_fd, (struct sockaddr *)&ctl_addr
		, offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
			failed = "bind";
		umask(ou);
	}

	/* 5 is a haphazardly chosen limit for the backlog.
	 * Rumour has it that this is the max on BSD systems.
	 */
	if (failed == NULL && listen(ctl_fd, 5) < 0)
		failed = "listen() on";

	return failed == NULL? NULL : builddiag("could not %s control socket: %d %s"
			, failed, errno, strerror(errno));
}

void
delete_ctl_socket(void)
{
	/* Is noting failure useful?  Not when used as preventative medicine. */
	unlink(ctl_addr.sun_path);
}

bool listening = FALSE; /* should we pay attention to IKE messages? */

struct iface *interfaces = NULL;        /* public interfaces */
struct raw_iface *ha_vip_ifaces = NULL; /* HA VIP Addresses */

/* Initialize the interface sockets. */

static void
mark_ifaces_dead(void)
{
	struct iface *p;

	for (p = interfaces; p != NULL; p = p->next)
		p->change = IFN_DELETE;
}

static void
free_dead_ifaces(void)
{
	struct iface *p;
	bool some_dead = FALSE
		, some_new = FALSE;

	for (p = interfaces; p != NULL; p = p->next)
	{
		if (p->change == IFN_DELETE)
		{
			plog("shutting down interface %s/%s %s"
				, p->vname, p->rname, ip_str(&p->addr));
			some_dead = TRUE;
		}
		else if (p->change == IFN_ADD)
		{
			some_new = TRUE;
		}
	}

	if (some_dead)
	{
		struct iface **pp;

		release_dead_interfaces();
		for (pp = &interfaces; (p = *pp) != NULL; )
		{
			if (p->change == IFN_DELETE)
			{
				*pp = p->next;  /* advance *pp */
				free(p->vname);
				free(p->rname);
				close(p->fd);
				free(p);
			}
			else
			{
				pp = &p->next;  /* advance pp */
			}
		}
	}

	/* this must be done after the release_dead_interfaces
	 * in case some to the newly unoriented connections can
	 * become oriented here.
	 */
	if (some_dead || some_new)
		check_orientations();
}

void
free_ifaces(void)
{
	mark_ifaces_dead();
	free_dead_ifaces();
}

struct raw_iface {
	ip_address addr;
	char name[IFNAMSIZ + 20];   /* what would be a safe size? */
	struct raw_iface *next;
};

/* Called to handle --interface <ifname>
 * Semantics: if specified, only these (real) interfaces are considered.
 */
static const char *pluto_ifn[10];
static int pluto_ifn_roof = 0;

bool
use_interface(const char *rifn)
{
	if (pluto_ifn_roof >= (int)countof(pluto_ifn))
	{
		return FALSE;
	}
	else
	{
		pluto_ifn[pluto_ifn_roof++] = rifn;
		return TRUE;
	}
}

#ifndef IPSECDEVPREFIX
# define IPSECDEVPREFIX "ipsec"
#endif

static struct raw_iface *
find_raw_ifaces4(void)
{
	int j;      /* index into buf */
	struct ifconf ifconf;
	struct ifreq buf[300];      /* for list of interfaces -- arbitrary limit */
	struct raw_iface *rifaces = NULL;
	int master_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);    /* Get a UDP socket */

	/* get list of interfaces with assigned IPv4 addresses from system */

	if (master_sock == -1)
		exit_log_errno((e, "socket() failed in find_raw_ifaces4()"));

	if (setsockopt(master_sock, SOL_SOCKET, SO_REUSEADDR
	, (const void *)&on, sizeof(on)) < 0)
		exit_log_errno((e, "setsockopt() in find_raw_ifaces4()"));

	/* bind the socket */
	{
		ip_address any;

		happy(anyaddr(AF_INET, &any));
		setportof(htons(pluto_port), &any);
		if (bind(master_sock, sockaddrof(&any), sockaddrlenof(&any)) < 0)
			exit_log_errno((e, "bind() failed in find_raw_ifaces4()"));
	}

	/* Get local interfaces.  See netdevice(7). */
	ifconf.ifc_len = sizeof(buf);
	ifconf.ifc_buf = (void *) buf;
	zero(buf);

	if (ioctl(master_sock, SIOCGIFCONF, &ifconf) == -1)
		exit_log_errno((e, "ioctl(SIOCGIFCONF) in find_raw_ifaces4()"));

	/* Add an entry to rifaces for each interesting interface. */
	for (j = 0; (j+1) * sizeof(*buf) <= (size_t)ifconf.ifc_len; j++)
	{
		struct raw_iface ri;
		const struct sockaddr_in *rs = (struct sockaddr_in *) &buf[j].ifr_addr;
		struct ifreq auxinfo;

		/* ignore all but AF_INET interfaces */
		if (rs->sin_family != AF_INET)
			continue;   /* not interesting */

		/* build a NUL-terminated copy of the rname field */
		memcpy(ri.name, buf[j].ifr_name, IFNAMSIZ);
		ri.name[IFNAMSIZ] = '\0';

		/* ignore if our interface names were specified, and this isn't one */
		if (pluto_ifn_roof != 0)
		{
			int i;

			for (i = 0; i != pluto_ifn_roof; i++)
				if (streq(ri.name, pluto_ifn[i]))
					break;
			if (i == pluto_ifn_roof)
				continue;       /* not found -- skip */
		}

		/* ignore if ha_vip interface names were specified, and this isn't one */
		if (ha_vip_ifaces != NULL)
		{
			struct raw_iface *ri_vip;

			for (ri_vip = ha_vip_ifaces; ri_vip != NULL; ri_vip = ri_vip->next)
				if (streq(ri_vip->name, ri.name))
					break;
			if (ri_vip != NULL && streq(ri_vip->name, ri.name))
				continue; /* Skip the ha vip interface */
		}

		/* Find out stuff about this interface.  See netdevice(7). */
		zero(&auxinfo); /* paranoia */
		memcpy(auxinfo.ifr_name, buf[j].ifr_name, IFNAMSIZ);
		if (ioctl(master_sock, SIOCGIFFLAGS, &auxinfo) == -1)
			exit_log_errno((e
				, "ioctl(SIOCGIFFLAGS) for %s in find_raw_ifaces4()"
				, ri.name));
		if (!(auxinfo.ifr_flags & IFF_UP))
			continue;   /* ignore an interface that isn't UP */

		/* ignore unconfigured interfaces */
		if (rs->sin_addr.s_addr == 0)
			continue;

		happy(initaddr((const void *)&rs->sin_addr, sizeof(struct in_addr)
			, AF_INET, &ri.addr));

		DBG(DBG_CONTROL, DBG_log("found %s with address %s"
			, ri.name, ip_str(&ri.addr)));
		ri.next = rifaces;
		rifaces = clone_thing(ri);
	}

	close(master_sock);

	/* Add our HA VIP interfaces */
	if(ha_vip_ifaces != NULL)
	{
		struct raw_iface ri_vip;
		struct raw_iface *ri_ptr;

		for (ri_ptr = ha_vip_ifaces; ri_ptr != NULL; ri_ptr = ri_ptr->next)
		{
			memcpy(&ri_vip, ri_ptr, sizeof(struct raw_iface));
			ri_vip.next = rifaces;
			rifaces = clone_thing(ri_vip);
		}
	}

	return rifaces;
}

static struct raw_iface *
find_raw_ifaces6(void)
{

	/* Get list of interfaces with IPv6 addresses from system from /proc/net/if_inet6).
	 *
	 * Documentation of format?
	 * RTFS: linux-2.2.16/net/ipv6/addrconf.c:iface_proc_info()
	 *       linux-2.4.9-13/net/ipv6/addrconf.c:iface_proc_info()
	 *
	 * Sample from Gerhard's laptop:
	 *  00000000000000000000000000000001 01 80 10 80       lo
	 *  30490009000000000000000000010002 02 40 00 80   ipsec0
	 *  30490009000000000000000000010002 07 40 00 80     eth0
	 *  fe80000000000000025004fffefd5484 02 0a 20 80   ipsec0
	 *  fe80000000000000025004fffefd5484 07 0a 20 80     eth0
	 *
	 * Each line contains:
	 * - IPv6 address: 16 bytes, in hex, no punctuation
	 * - ifindex: 1 byte, in hex
	 * - prefix_len: 1 byte, in hex
	 * - scope (e.g. global, link local): 1 byte, in hex
	 * - flags: 1 byte, in hex
	 * - device name: string, followed by '\n'
	 */
	struct raw_iface *rifaces = NULL;
	static const char proc_name[] = "/proc/net/if_inet6";
	FILE *proc_sock = fopen(proc_name, "r");

	if (proc_sock == NULL)
	{
		DBG(DBG_CONTROL, DBG_log("could not open %s", proc_name));
	}
	else
	{
		for (;;)
		{
			struct raw_iface ri;
			unsigned short xb[8];       /* IPv6 address as 8 16-bit chunks */
			char sb[8*5];       /* IPv6 address as string-with-colons */
			unsigned int if_idx;        /* proc field, not used */
			unsigned int plen;  /* proc field, not used */
			unsigned int scope; /* proc field, used to exclude link-local */
			unsigned int dad_status;    /* proc field, not used */
			/* ??? I hate and distrust scanf -- DHR */
			int r = fscanf(proc_sock
				, "%4hx%4hx%4hx%4hx%4hx%4hx%4hx%4hx"
				  " %02x %02x %02x %02x %20s\n"
				, xb+0, xb+1, xb+2, xb+3, xb+4, xb+5, xb+6, xb+7
				, &if_idx, &plen, &scope, &dad_status, ri.name);

			/* ??? we should diagnose any problems */
			if (r != 13)
				break;

			/* ignore addresses with link local scope.
			 * From linux-2.4.9-13/include/net/ipv6.h:
			 * IPV6_ADDR_LINKLOCAL      0x0020U
			 * IPV6_ADDR_SCOPE_MASK     0x00f0U
			 */
			if ((scope & 0x00f0U) == 0x0020U)
				continue;

			snprintf(sb, sizeof(sb)
				, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
				, xb[0], xb[1], xb[2], xb[3], xb[4], xb[5], xb[6], xb[7]);

			happy(ttoaddr(sb, 0, AF_INET6, &ri.addr));

			if (!isunspecaddr(&ri.addr))
			{
				DBG(DBG_CONTROL
					, DBG_log("found %s with address %s"
						, ri.name, sb));
				ri.next = rifaces;
				rifaces = clone_thing(ri);
			}
		}
		fclose(proc_sock);
	}

	return rifaces;
}

#if 1
static int
create_socket(struct raw_iface *ifp, const char *v_name, int port)
{
	int fd = socket(addrtypeof(&ifp->addr), SOCK_DGRAM, IPPROTO_UDP);
	int fcntl_flags;

	if (fd < 0)
	{
		log_errno((e, "socket() in process_raw_ifaces()"));
		return -1;
	}

#if 1
	/* Set socket Nonblocking */
	if ((fcntl_flags=fcntl(fd, F_GETFL)) >= 0) {
		if (!(fcntl_flags & O_NONBLOCK)) {
			fcntl_flags |= O_NONBLOCK;
			fcntl(fd, F_SETFL, fcntl_flags);
		}
	}
#endif

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
	{
		log_errno((e, "fcntl(,, FD_CLOEXEC) in process_raw_ifaces()"));
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR
	, (const void *)&on, sizeof(on)) < 0)
	{
		log_errno((e, "setsockopt SO_REUSEADDR in process_raw_ifaces()"));
		close(fd);
		return -1;
	}

	/* To improve error reporting.  See ip(7). */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	if (setsockopt(fd, SOL_IP, IP_RECVERR
	, (const void *)&on, sizeof(on)) < 0)
	{
		log_errno((e, "setsockopt IP_RECVERR in process_raw_ifaces()"));
		close(fd);
		return -1;
	}
#endif

	/* With IPv6, there is no fragmentation after
	 * it leaves our interface.  PMTU discovery
	 * is mandatory but doesn't work well with IKE (why?).
	 * So we must set the IPV6_USE_MIN_MTU option.
	 * See draft-ietf-ipngwg-rfc2292bis-01.txt 11.1
	 */
#ifdef IPV6_USE_MIN_MTU /* YUCK: not always defined */
	if (addrtypeof(&ifp->addr) == AF_INET6
	&& setsockopt(fd, SOL_SOCKET, IPV6_USE_MIN_MTU
	  , (const void *)&on, sizeof(on)) < 0)
	{
		log_errno((e, "setsockopt IPV6_USE_MIN_MTU in process_raw_ifaces()"));
		close(fd);
		return -1;
	}
#endif

#if defined(linux) && defined(KERNEL26_SUPPORT)
	if (!no_klips && kernel_ops->type == KERNEL_TYPE_LINUX)
	{
		struct sadb_x_policy policy;
		int level, opt;

		policy.sadb_x_policy_len = sizeof(policy) / IPSEC_PFKEYv2_ALIGN;
		policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
		policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
		policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
		policy.sadb_x_policy_reserved = 0;
		policy.sadb_x_policy_id = 0;
		policy.sadb_x_policy_reserved2 = 0;

		if (addrtypeof(&ifp->addr) == AF_INET6)
		{
			level = IPPROTO_IPV6;
			opt = IPV6_IPSEC_POLICY;
		}
		else
		{
			level = IPPROTO_IP;
			opt = IP_IPSEC_POLICY;
		}

		if (setsockopt(fd, level, opt
		  , &policy, sizeof(policy)) < 0)
		{
			log_errno((e, "setsockopt IPSEC_POLICY in process_raw_ifaces()"));
			close(fd);
			return -1;
		}

		policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;

		if (setsockopt(fd, level, opt
		  , &policy, sizeof(policy)) < 0)
		{
			log_errno((e, "setsockopt IPSEC_POLICY in process_raw_ifaces()"));
			close(fd);
			return -1;
		}
	}
#endif

	setportof(htons(port), &ifp->addr);
	if (bind(fd, sockaddrof(&ifp->addr), sockaddrlenof(&ifp->addr)) < 0)
	{
		log_errno((e, "bind() for %s/%s %s:%u in process_raw_ifaces()"
			, ifp->name, v_name
			, ip_str(&ifp->addr), (unsigned) port));
		close(fd);
		return -1;
	}
	setportof(htons(pluto_port), &ifp->addr);
	return fd;
}
#endif

static void
process_raw_ifaces(struct raw_iface *rifaces)
{
	struct raw_iface *ifp;

	/* Find all virtual/real interface pairs.
	 * For each real interface...
	 */
	for (ifp = rifaces; ifp != NULL; ifp = ifp->next)
	{
		struct raw_iface *v = NULL;     /* matching ipsecX interface */
		struct raw_iface fake_v;
		bool after = FALSE; /* has vfp passed ifp on the list? */
		bool bad = FALSE;
		struct raw_iface *vfp;

		/* ignore if virtual (ipsec*) interface */
		if (strneq(ifp->name, IPSECDEVPREFIX, sizeof(IPSECDEVPREFIX)-1))
		{
			continue;
		}

		for (vfp = rifaces; vfp != NULL; vfp = vfp->next)
		{
			if (vfp == ifp)
			{
				after = TRUE;
			}
			else if (sameaddr(&ifp->addr, &vfp->addr))
			{
				/* Different entries with matching IP addresses.
				 * Many interesting cases.
				 */
				if (strneq(vfp->name, IPSECDEVPREFIX, sizeof(IPSECDEVPREFIX)-1))
				{
					if (v != NULL  && !streq(v->name, vfp->name))
					{
						loglog(RC_LOG_SERIOUS
							, "ipsec interfaces %s and %s share same address %s"
							, v->name, vfp->name, ip_str(&ifp->addr));
						bad = TRUE;
					}
					else
					{
						v = vfp;        /* current winner */
					}
				}
				else
				{
					/* ugh: a second real interface with the same IP address
					 * "after" allows us to avoid double reporting.
					 */
#if defined(linux) && defined(KERNEL26_SUPPORT)
					if (!no_klips && kernel_ops->type == KERNEL_TYPE_LINUX)
					{
						if (after)
						{
							bad = TRUE;
							break;
						}
						continue;
					}
#endif
					if (after)
					{
						loglog(RC_LOG_SERIOUS
							, "IP interfaces %s and %s share address %s!"
							, ifp->name, vfp->name, ip_str(&ifp->addr));
					}
					bad = TRUE;
				}
			}
		}

		if (bad)
			continue;

#if defined(linux) && defined(KERNEL26_SUPPORT)
		if (!no_klips && kernel_ops->type == KERNEL_TYPE_LINUX)
		{
			v = ifp;
			goto add_entry;
		}
#endif

		/* what if we didn't find a virtual interface? */
		if (v == NULL)
		{
			if (no_klips)
			{
				/* kludge for testing: invent a virtual device */
				static const char fvp[] = "virtual";
				fake_v = *ifp;
				passert(sizeof(fake_v.name) > sizeof(fvp));
				strcpy(fake_v.name, fvp);
				addrtot(&ifp->addr, 0, fake_v.name + sizeof(fvp) - 1
					, sizeof(fake_v.name) - (sizeof(fvp) - 1));
				v = &fake_v;
			}
			else
			{
				DBG(DBG_CONTROL,
						DBG_log("IP interface %s %s has no matching ipsec* interface -- ignored"
							, ifp->name, ip_str(&ifp->addr)));
				continue;
			}
		}

		/* We've got all we need; see if this is a new thing:
		 * search old interfaces list.
		 */
#if defined(linux) && defined(KERNEL26_SUPPORT)
add_entry:
#endif
		{
			struct iface **p = &interfaces;

			for (;;)
			{
				struct iface *q = *p;

				/* search is over if at end of list */
				if (q == NULL)
				{
					/* matches nothing -- create a new entry */
					int fd = -1;

					if (ha_vip_ifaces != NULL)
					{
						struct raw_iface *ri_ptr;

						for (ri_ptr = ha_vip_ifaces; ri_ptr != NULL; ri_ptr = ri_ptr->next)
							if (streq(ri_ptr->name, ifp->name))
								fd = INT_MAX; /* Lets hope this fd isnt used otherwise ;) */
					}

					if (fd < 0)
						fd = create_socket(ifp, v->name, pluto_port);

					if (fd < 0)
						break;

					if (nat_traversal_support_non_ike
					&& addrtypeof(&ifp->addr) == AF_INET)
					{
						nat_traversal_espinudp_socket(fd, ESPINUDP_WITH_NON_IKE);
					}

					q = malloc_thing(struct iface);
					zero(q);
					q->rname = clone_str(ifp->name);
					q->vname = clone_str(v->name);
					q->addr = ifp->addr;
					q->fd = fd;
					q->next = interfaces;
					q->change = IFN_ADD;
					interfaces = q;
					plog("adding interface %s/%s %s:%d"
						, q->vname, q->rname, ip_str(&q->addr), pluto_port);

					if (nat_traversal_support_port_floating
					&& addrtypeof(&ifp->addr) == AF_INET)
					{
						fd = -1;

						if (ha_vip_ifaces != NULL)
						{
							struct raw_iface *ri_ptr;

							for (ri_ptr = ha_vip_ifaces; ri_ptr != NULL; ri_ptr = ri_ptr->next)
								if (streq(ri_ptr->name, ifp->name))
									fd = INT_MAX; /* Lets hope this fd isnt used otherwise ;) */
						}

						if (fd < 0)
							fd = create_socket(ifp, v->name, NAT_T_IKE_FLOAT_PORT);

						if (fd < 0)
							break;
						nat_traversal_espinudp_socket(fd,
							ESPINUDP_WITH_NON_ESP);
						q = malloc_thing(struct iface);
						zero(q);
						q->rname = clone_str(ifp->name);
						q->vname = clone_str(v->name);
						q->addr = ifp->addr;
						setportof(htons(NAT_T_IKE_FLOAT_PORT), &q->addr);
						q->fd = fd;
						q->next = interfaces;
						q->change = IFN_ADD;
						q->ike_float = TRUE;
						interfaces = q;
						plog("adding interface %s/%s %s:%d",
						q->vname, q->rname, ip_str(&q->addr), NAT_T_IKE_FLOAT_PORT);
					}
					break;
				}

				/* search over if matching old entry found */
				if (streq(q->rname, ifp->name)
				&& streq(q->vname, v->name)
				&& sameaddr(&q->addr, &ifp->addr))
				{
					/* matches -- rejuvinate old entry */
					q->change = IFN_KEEP;

					/* look for other interfaces to keep (due to NAT-T) */
					for (q = q->next ; q ; q = q->next)
					{
						if (streq(q->rname, ifp->name)
						&& streq(q->vname, v->name)
						&& sameaddr(&q->addr, &ifp->addr))
						{
							q->change = IFN_KEEP;
						}
					}
					break;
				}

				/* try again */
				p = &q->next;
			} /* for (;;) */
		}
	}

	/* delete the raw interfaces list */
	while (rifaces != NULL)
	{
		struct raw_iface *t = rifaces;

		rifaces = t->next;
		free(t);
	}
}

void
find_ifaces(void)
{
	mark_ifaces_dead();
	process_raw_ifaces(find_raw_ifaces4());
	process_raw_ifaces(find_raw_ifaces6());

	free_dead_ifaces();     /* ditch remaining old entries */

	if (interfaces == NULL)
		loglog(RC_LOG_SERIOUS, "no public interfaces found");
}

void
show_ifaces_status(void)
{
	struct iface *p;

	/* Display HA Informations if enabled */
	if (ha_interface != NULL) {
		whack_log(RC_COMMENT, "HA System active on %s/%s. Current mode is %s. Seqdiff in: %u Seqdiff out: %u",
			ha_interface, inet_ntoa(ha_mcast_addr), ha_master == 1 ? "Master" : (ha_master == 0 ? "Slave" : "Init"), ha_seqdiff_in, ha_seqdiff_out);
		whack_log(RC_COMMENT, BLANK_FORMAT);  /* spacer */
	}

	for (p = interfaces; p != NULL; p = p->next)
		whack_log(RC_COMMENT, "interface %s/%s %s:%d"
			, p->vname, p->rname, ip_str(&p->addr), ntohs(portof(&p->addr)));
}

void
show_debug_status(void)
{
#ifdef DEBUG
	whack_log(RC_COMMENT, "debug options: %s"
		, bitnamesof(debug_bit_names, cur_debugging));
#endif
}

static volatile sig_atomic_t sighupflag = FALSE;

static void
huphandler(int sig UNUSED)
{
	sighupflag = TRUE;
}

static volatile sig_atomic_t sigtermflag = FALSE;

static void
termhandler(int sig UNUSED)
{
	sigtermflag = TRUE;
}

/* call_server listens for incoming ISAKMP packets and Whack messages,
 * and handles timer events.
 */
void
call_server(void)
{
	struct iface *ifp;

	/* catch SIGHUP and SIGTERM */
	{
		int r;
		struct sigaction act;

		act.sa_handler = &huphandler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;       /* no SA_ONESHOT, no SA_RESTART, no nothing */
		r = sigaction(SIGHUP, &act, NULL);
		passert(r == 0);

		act.sa_handler = &termhandler;
		r = sigaction(SIGTERM, &act, NULL);
		passert(r == 0);
	}

	for (;;)
	{
		fd_set readfds;
		fd_set writefds;
		int ndes;

		/* wait for next interesting thing */

		for (;;)
		{
			long next_time = next_event();   /* time to any pending timer event */
			int maxfd = ctl_fd;

			if (sigtermflag)
				exit_pluto(0);

			if (sighupflag)
			{
				/* Ignorant folks think poking any daemon with SIGHUP
				 * is polite.  We catch it and tell them otherwise.
				 * There is one use: unsticking a hung recvfrom.
				 * This sticking happens sometimes -- kernel bug?
				 */
				sighupflag = FALSE;
				plog("Pluto ignores SIGHUP -- perhaps you want \"whack --listen\"");
			}

			FD_ZERO(&readfds);
			FD_ZERO(&writefds);
			FD_SET(ctl_fd, &readfds);

			if (ha_interface != NULL) {
				if (maxfd < ha_sock)
					maxfd = ha_sock;
				FD_SET(ha_sock, &readfds);
			}

			/* the only write file-descriptor of interest */
			if (adns_qfd != NULL_FD && unsent_ADNS_queries)
			{
				if (maxfd < adns_qfd)
					maxfd = adns_qfd;
				FD_SET(adns_qfd, &writefds);
			}

			if (adns_afd != NULL_FD)
			{
				if (maxfd < adns_afd)
					maxfd = adns_afd;
				FD_SET(adns_afd, &readfds);
			}

#ifdef KLIPS
			if (!no_klips)
			{
				int fd = *kernel_ops->async_fdp;

				if (kernel_ops->process_queue)
					kernel_ops->process_queue();
				if (maxfd < fd)
					maxfd = fd;
				passert(!FD_ISSET(fd, &readfds));
				FD_SET(fd, &readfds);
			}
#endif

			if (listening)
			{
				for (ifp = interfaces; ifp != NULL; ifp = ifp->next)
				{
					if (maxfd < ifp->fd)
						maxfd = ifp->fd;
					passert(!FD_ISSET(ifp->fd, &readfds));
					FD_SET(ifp->fd, &readfds);
				}
			}

			if (next_time == -1)
			{
				/* select without timer */

				ndes = select(maxfd + 1, &readfds, &writefds, NULL, NULL);
			}
			else if (next_time == 0)
			{
				/* timer without select: there is a timer event pending,
				 * and it should fire now so don't bother to do the select.
				 */
				ndes = 0;       /* signify timer expiration */
			}
			else
			{
				/* select with timer */

				struct timeval tm;

				tm.tv_sec = next_time;
				tm.tv_usec = 0;
				ndes = select(maxfd + 1, &readfds, &writefds, NULL, &tm);
			}

			if (ndes != -1)
				break;  /* success */

			if (errno != EINTR)
				exit_log_errno((e, "select() failed in call_server()"));

			/* retry if terminated by signal */
		}

		/* figure out what is interesting */

		if (ndes == 0)
		{
			/* timer event */

			DBG(DBG_CONTROL,
				DBG_log(BLANK_FORMAT);
				DBG_log("*time to handle event"));

			handle_timer_event();
			passert(GLOBALS_ARE_RESET());
		}
		else
		{
			/* at least one file descriptor is ready */

			if (adns_qfd != NULL_FD && FD_ISSET(adns_qfd, &writefds))
			{
				passert(ndes > 0);
				send_unsent_ADNS_queries();
				passert(GLOBALS_ARE_RESET());
				ndes--;
			}

			if (adns_afd != NULL_FD && FD_ISSET(adns_afd, &readfds))
			{
				passert(ndes > 0);
				DBG(DBG_CONTROL,
					DBG_log(BLANK_FORMAT);
					DBG_log("*received adns message"));
				handle_adns_answer();
				passert(GLOBALS_ARE_RESET());
				ndes--;
			}

#ifdef KLIPS
			if (!no_klips && FD_ISSET(*kernel_ops->async_fdp, &readfds))
			{
				passert(ndes > 0);
				DBG(DBG_CONTROL,
					DBG_log(BLANK_FORMAT);
					DBG_log("*received kernel message"));
				kernel_ops->process_msg();
				passert(GLOBALS_ARE_RESET());
				ndes--;
			}
#endif
			if (listening)
			{
				for (ifp = interfaces; ifp != NULL; ifp = ifp->next)
				{
					if (FD_ISSET(ifp->fd, &readfds))
					{
						/* comm_handle will print DBG_CONTROL intro,
						 * with more info than we have here.
						 */

						passert(ndes > 0);
						comm_handle(ifp);
						passert(GLOBALS_ARE_RESET());
						ndes--;
					}
				}
			}

			if (FD_ISSET(ctl_fd, &readfds))
			{
				passert(ndes > 0);
				DBG(DBG_CONTROL,
					DBG_log(BLANK_FORMAT);
					DBG_log("*received whack message"));
				whack_handle(ctl_fd);
				passert(GLOBALS_ARE_RESET());
				ndes--;
			}

			/* Look for new ha multicast messages if HA System is enabled */
			if (ha_interface != NULL && FD_ISSET(ha_sock, &readfds))
			{
				struct ha_sync_hdr sync_hdr;
				struct ha_sync_msg *sync_msg;
				struct sockaddr_in saddr;
				socklen_t socklen = sizeof(saddr);
				int msg_length;
				ssize_t status;

				passert(ndes > 0);

				/* Take a look at the header to get the message size */
				if (recvfrom(ha_sock, &sync_hdr, sizeof(sync_hdr), MSG_PEEK,
					(struct sockaddr *) &saddr, &socklen) != sizeof(sync_hdr))
				{
					plog("HA System: Failed to peek at message header.");
					goto ha_out;
				}

				if (sync_hdr.magic != SA_SYNC_MAGIC)
				{
					plog("HA System: Master and Slave seems to run different versions, HA message ignored!");
					plog("\t Please upgrade to ensure a working HA system.");
					recv(ha_sock, &sync_hdr, sizeof(sync_hdr), 0);
					goto ha_out;
				}

				msg_length = sync_hdr.length + sizeof(sync_hdr);
				sync_msg = malloc(msg_length);
				if (sync_msg == NULL)
				{
					plog("HA System: Failed to allocate memory for sync message.");
					goto ha_out;
				}

				do
				{
					status = recvfrom(ha_sock, sync_msg, msg_length, MSG_WAITALL,
									  (struct sockaddr *) &saddr, &socklen);
				} while (status == -1 && errno == EINTR);

				if (status != msg_length)
				{
					plog("HA System: Failed to receive HA multicast message.");
					goto ha_out_free;
				}

				DBG(DBG_HA, DBG_log("HA System: received %N message (%d bytes) from %s",
					sync_msg_names, sync_hdr.type, msg_length, inet_ntoa(saddr.sin_addr)));
				process_sync_msg(sync_msg, saddr.sin_addr);
ha_out_free:
				free(sync_msg);
ha_out:
				passert(GLOBALS_ARE_RESET());
				ndes--;
			}

			passert(ndes == 0);
		}
	}
}

int
open_ha_iface(void)
{
	int status;
	int fd;
	struct sockaddr_in saddr;
	struct sockaddr_in *ha_saddr;
	struct ifreq ha_ifreq;
	struct ip_mreq imreq;
	u_char sock_options;

	/* set content of struct saddr, ha_saddr and imreq to zero */
	memset(&saddr, 0, sizeof(struct sockaddr_in));
	memset(&imreq, 0, sizeof(struct ip_mreq));

	/* get ip address of ha interface and save to ha_ifreq*/
	strcpy(ha_ifreq.ifr_name, ha_interface);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	status = ioctl(fd, SIOCGIFADDR, &ha_ifreq);
	if (status < 0)
		return -1;

	/* open a UDP socket */
	ha_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (ha_sock < 0)
		return -1;

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(SA_SYNC_PORT);
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);

	status = bind(ha_sock, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in));

	if (status < 0)
		return -1;

	/* Bind UDP socket to ha interface */
	status = setsockopt(ha_sock, SOL_SOCKET, SO_BINDTODEVICE, &ha_ifreq, sizeof(struct ifreq) );

	if (status < 0)
		return -1;

	/* Bypass routing */
	sock_options = 1;
	setsockopt(ha_sock, SOL_SOCKET, SO_DONTROUTE, &sock_options, sizeof(sock_options));

	/* Disable loop */
	sock_options = 0;
	setsockopt(ha_sock, IPPROTO_IP, IP_MULTICAST_LOOP, &sock_options, sizeof(sock_options));

	/* Join multicast group */
	ha_saddr = (struct sockaddr_in *) &ha_ifreq.ifr_addr; /* Needed to convert between different types */

	imreq.imr_multiaddr = ha_mcast_addr;
	imreq.imr_interface = ha_saddr->sin_addr;
	status = setsockopt(ha_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const void *) &imreq, sizeof(struct ip_mreq));

	if (status < 0)
		return -1;

	return TRUE;
}

void
close_ha_iface(void)
{
	/* shutdown socket */
	shutdown(ha_sock, 2);
	/* close socket */
	close(ha_sock);
}

int
add_ha_vips(char *optarg)
{
	ip_address dst;
	char *ptr, *ptr2;
	struct raw_iface ri;
	int len = 0;

	do
	{
		ptr = strchr(optarg, ',');

		if (ptr == NULL)
			len = strlen(optarg);
		else
			len = ptr - optarg;

		ptr2 = strchr(optarg, '=');

		if (ptr2 == NULL || ptr2 - optarg > len)
			return 1;

		if (ttoaddr(ptr2 + 1, len - (ptr2 - optarg) - 1, AF_INET, &dst) == NULL)
		{
			ri.addr = dst;
			*ptr2 = 0;
			sprintf(&ri.name[0], "%s", optarg);
			ri.next = ha_vip_ifaces;
			ha_vip_ifaces = clone_thing(ri);
		}
		else
			return 1;

		if (ptr == NULL)
			len = 0;
		else
			optarg = ptr + 1;
	} while (len > 0);

	return 0;
}

int
listen_ha_vips()
{
	struct iface *p;
	struct raw_iface *ri_ptr;

	if (ha_vip_ifaces == NULL)
		return 0;

	for (ri_ptr = ha_vip_ifaces; ri_ptr != NULL; ri_ptr = ri_ptr->next)
	{
		for (p = interfaces; p != NULL; p = p->next)
		{
			if (streq(ri_ptr->name, p->rname))
			{
				if (p->ike_float)
					p->fd = create_socket(ri_ptr, p->vname, NAT_T_IKE_FLOAT_PORT);
				else
					p->fd = create_socket(ri_ptr, p->vname, pluto_port);
				if (p->fd < 0)
					return 1;
			}
		}
	}

	return 0;
}

void
unlisten_ha_vips()
{
	struct iface *p;
	struct raw_iface *ri_ptr;

	if (ha_vip_ifaces == NULL)
		return;

	for (ri_ptr = ha_vip_ifaces; ri_ptr != NULL; ri_ptr = ri_ptr->next)
	{
		for (p = interfaces; p != NULL; p = p->next)
		{
			if (streq(ri_ptr->name, p->rname))
			{
				close(p->fd);
				p->fd = INT_MAX;
			}
		}
	}
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * End Variables:
 */
