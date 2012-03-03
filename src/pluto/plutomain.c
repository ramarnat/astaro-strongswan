/* Pluto main program
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001 D. Hugh Redelmeier.
 * Copyright (C) 2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <getopt.h>
#include <resolv.h>
#include <arpa/nameser.h>       /* missing from <resolv.h> on old systems */
#include <sys/queue.h>
#include <sys/prctl.h>
#include <pwd.h>
#include <grp.h>

#ifdef CAPABILITIES
#include <sys/capability.h>
#endif /* CAPABILITIES */

#include <freeswan.h>

#include <hydra.h>
#include <library.h>
#include <debug.h>
#include <utils/enumerator.h>
#include <utils/optionsfrom.h>

#include <pfkeyv2.h>
#include <pfkey.h>

#include "constants.h"
#include "defs.h"
#include "myid.h"
#include "ca.h"
#include "certs.h"
#include "ac.h"
#include "connections.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "server.h"
#include "kernel.h"
#include "log.h"
#include "keys.h"
#include "adns.h"       /* needs <resolv.h> */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "state.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "ocsp.h"
#include "crl.h"
#include "fetch.h"
#include "crypto.h"
#include "nat_traversal.h"
#include "virtual.h"
#include "timer.h"
#include "vendor.h"
#include "builder.h"
#include "whack_attribute.h"
#include "pluto.h"

static void usage(const char *mess)
{
	if (mess != NULL && *mess != '\0')
		fprintf(stderr, "%s\n", mess);
	fprintf(stderr
		, "Usage: pluto"
			" [--help]"
			" [--version]"
			" [--optionsfrom <filename>]"
			" \\\n\t"
			"[--nofork]"
			" [--stderrlog]"
			" [--noklips]"
			" [--nocrsend]"
			" \\\n\t"
			"[--strictcrlpolicy]"
			" [--crlcheckinterval <interval>]"
			" [--cachecrls]"
			" [--uniqueids]"
			" \\\n\t"
			"[--interface <ifname>]"
			" [--ikeport <port-number>]"
			" \\\n\t"
			"[--ctlbase <path>]"
			" \\\n\t"
			"[--perpeerlogbase <path>] [--perpeerlog]"
			" \\\n\t"
			"[--secretsfile <secrets-file>]"
			" [--policygroupsdir <policygroups-dir>]"
			" \\\n\t"
			"[--adns <pathname>]"
			"[--pkcs11module <path>]"
			"[--pkcs11keepstate]"
			"[--pkcs11initargs <string>]"
#ifdef DEBUG
			" \\\n\t"
			"[--debug-none]"
			" [--debug-all]"
			" \\\n\t"
			"[--debug-raw]"
			" [--debug-crypt]"
			" [--debug-parsing]"
			" [--debug-emitting]"
			" \\\n\t"
			"[--debug-control]"
			" [--debug-lifecycle]"
			" [--debug-klips]"
			" [--debug-dns]"
			" \\\n\t"
			"[--debug-oppo]"
			" [--debug-controlmore]"
			" [--debug-private]"
			" [--debug-natt]"
#endif
		    " \\\n\t"
			"[--nat_traversal] [--keep_alive <delay_sec>]"
			" \\\n\t"
			"[--force_keepalive] [--disable_port_floating]"
		    " \\\n\t"
		    "[--virtual_private <network_list>]"
			"\n"
		    "strongSwan "VERSION"\n");
	exit_pluto(mess == NULL? 0 : 1);
}


/* lock file support
 * - provides convenient way for scripts to find Pluto's pid
 * - prevents multiple Plutos competing for the same port
 * - same basename as unix domain control socket
 * NOTE: will not take account of sharing LOCK_DIR with other systems.
 */

static char pluto_lock[sizeof(ctl_addr.sun_path)] = DEFAULT_CTLBASE LOCK_SUFFIX;
static bool pluto_lock_created = FALSE;

/* create lockfile, or die in the attempt */
static int create_lock(void)
{
	int fd = open(pluto_lock, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC
		, S_IRUSR | S_IRGRP | S_IROTH);

	if (fd < 0)
	{
		if (errno == EEXIST)
		{
			fprintf(stderr, "pluto: lock file \"%s\" already exists\n"
				, pluto_lock);
			exit_pluto(10);
		}
		else
		{
			fprintf(stderr
				, "pluto: unable to create lock file \"%s\" (%d %s)\n"
				, pluto_lock, errno, strerror(errno));
			exit_pluto(1);
		}
	}
	pluto_lock_created = TRUE;
	return fd;
}

static bool fill_lock(int lockfd, pid_t pid)
{
	char buf[30];       /* holds "<pid>\n" */
	int len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int) pid);
	bool ok = len > 0 && write(lockfd, buf, len) == len;

	close(lockfd);
	return ok;
}

static void delete_lock(void)
{
	if (pluto_lock_created)
	{
		delete_ctl_socket();
		unlink(pluto_lock);     /* is noting failure useful? */
	}
}


/* by default pluto sends certificate requests to its peers */
bool no_cr_send = FALSE;

/* by default the CRL policy is lenient */
bool strict_crl_policy = FALSE;

/* by default CRLs are cached locally as files */
bool cache_crls = FALSE;

/* by default pluto does not check crls dynamically */
long crl_check_interval = 0;

/* path to the PKCS#11 module */
char *pkcs11_module_path = NULL;

/* by default pluto logs out after every smartcard use */
bool pkcs11_keep_state = FALSE;

/* by default pluto does not allow pkcs11 proxy access via whack */
bool pkcs11_proxy = FALSE;

/* argument string to pass to PKCS#11 module.
 * Not used for compliant modules, just for NSS softoken
 */
static const char *pkcs11_init_args = NULL;

/* options read by optionsfrom */
options_t *options;

/**
 * Log loaded plugins
 */
static void print_plugins()
{
	char buf[BUF_LEN], *plugin;
	int len = 0;
	enumerator_t *enumerator;

	buf[0] = '\0';
	enumerator = lib->plugins->create_plugin_enumerator(lib->plugins);
	while (len < BUF_LEN && enumerator->enumerate(enumerator, &plugin))
	{
		len += snprintf(&buf[len], BUF_LEN-len, "%s ", plugin);
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_DMN, "loaded plugins: %s", buf);
}

int main(int argc, char **argv)
{
	bool fork_desired = TRUE;
	bool log_to_stderr_desired = FALSE;
	bool nat_traversal = FALSE;
	bool nat_t_spf = TRUE;  /* support port floating */
	unsigned int keep_alive = 0;
	bool force_keepalive = FALSE;
	char *virtual_private = NULL;
	int lockfd;
#ifdef CAPABILITIES
	cap_t caps;
	int keep[] = { CAP_NET_ADMIN, CAP_NET_BIND_SERVICE };
#endif /* CAPABILITIES */

	/* initialize library and optionsfrom */
	if (!library_init(NULL))
	{
		library_deinit();
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (!libhydra_init("pluto"))
	{
		libhydra_deinit();
		library_deinit();
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	if (!pluto_init(argv[0]))
	{
		pluto_deinit();
		libhydra_deinit();
		library_deinit();
		exit(SS_RC_DAEMON_INTEGRITY);
	}
	options = options_create();

	/* handle arguments */
	for (;;)
	{
#       define DBG_OFFSET 256
		static const struct option long_opts[] = {
			/* name, has_arg, flag, val */
			{ "help", no_argument, NULL, 'h' },
			{ "version", no_argument, NULL, 'v' },
			{ "optionsfrom", required_argument, NULL, '+' },
			{ "nofork", no_argument, NULL, 'd' },
			{ "stderrlog", no_argument, NULL, 'e' },
			{ "noklips", no_argument, NULL, 'n' },
			{ "nocrsend", no_argument, NULL, 'c' },
			{ "strictcrlpolicy", no_argument, NULL, 'r' },
			{ "crlcheckinterval", required_argument, NULL, 'x'},
			{ "cachecrls", no_argument, NULL, 'C' },
			{ "uniqueids", no_argument, NULL, 'u' },
			{ "interface", required_argument, NULL, 'i' },
			{ "ikeport", required_argument, NULL, 'p' },
			{ "ctlbase", required_argument, NULL, 'b' },
			{ "secretsfile", required_argument, NULL, 's' },
			{ "foodgroupsdir", required_argument, NULL, 'f' },
			{ "perpeerlogbase", required_argument, NULL, 'P' },
			{ "perpeerlog", no_argument, NULL, 'l' },
			{ "policygroupsdir", required_argument, NULL, 'f' },
#ifdef USE_LWRES
			{ "lwdnsq", required_argument, NULL, 'a' },
#else /* !USE_LWRES */
			{ "adns", required_argument, NULL, 'a' },
#endif /* !USE_LWRES */
			{ "pkcs11module", required_argument, NULL, 'm' },
			{ "pkcs11keepstate", no_argument, NULL, 'k' },
			{ "pkcs11initargs", required_argument, NULL, 'z' },
			{ "pkcs11proxy", no_argument, NULL, 'y' },
			{ "nat_traversal", no_argument, NULL, '1' },
			{ "keep_alive", required_argument, NULL, '2' },
			{ "force_keepalive", no_argument, NULL, '3' },
			{ "disable_port_floating", no_argument, NULL, '4' },
			{ "debug-natt", no_argument, NULL, '5' },
			{ "virtual_private", required_argument, NULL, '6' },
#ifdef DEBUG
			{ "debug-none", no_argument, NULL, 'N' },
			{ "debug-all", no_argument, NULL, 'A' },
			{ "debug-raw", no_argument, NULL, DBG_RAW + DBG_OFFSET },
			{ "debug-crypt", no_argument, NULL, DBG_CRYPT + DBG_OFFSET },
			{ "debug-parsing", no_argument, NULL, DBG_PARSING + DBG_OFFSET },
			{ "debug-emitting", no_argument, NULL, DBG_EMITTING + DBG_OFFSET },
			{ "debug-control", no_argument, NULL, DBG_CONTROL + DBG_OFFSET },
			{ "debug-lifecycle", no_argument, NULL, DBG_LIFECYCLE + DBG_OFFSET },
			{ "debug-klips", no_argument, NULL, DBG_KLIPS + DBG_OFFSET },
			{ "debug-dns", no_argument, NULL, DBG_DNS + DBG_OFFSET },
			{ "debug-oppo", no_argument, NULL, DBG_OPPO + DBG_OFFSET },
			{ "debug-controlmore", no_argument, NULL, DBG_CONTROLMORE + DBG_OFFSET },
			{ "debug-private", no_argument, NULL, DBG_PRIVATE + DBG_OFFSET },

			{ "impair-delay-adns-key-answer", no_argument, NULL, IMPAIR_DELAY_ADNS_KEY_ANSWER + DBG_OFFSET },
			{ "impair-delay-adns-txt-answer", no_argument, NULL, IMPAIR_DELAY_ADNS_TXT_ANSWER + DBG_OFFSET },
			{ "impair-bust-mi2", no_argument, NULL, IMPAIR_BUST_MI2 + DBG_OFFSET },
			{ "impair-bust-mr2", no_argument, NULL, IMPAIR_BUST_MR2 + DBG_OFFSET },
#endif
			{ 0,0,0,0 }
			};
		/* Note: we don't like the way short options get parsed
		 * by getopt_long, so we simply pass an empty string as
		 * the list.  It could be "hvdenp:l:s:" "NARXPECK".
		 */
		int c = getopt_long(argc, argv, "", long_opts, NULL);

		/* Note: "breaking" from case terminates loop */
		switch (c)
		{
		case EOF:       /* end of flags */
			break;

		case 0: /* long option already handled */
			continue;

		case ':':       /* diagnostic already printed by getopt_long */
		case '?':       /* diagnostic already printed by getopt_long */
			usage("");
			break;   /* not actually reached */

		case 'h':       /* --help */
			usage(NULL);
			break;      /* not actually reached */

		case 'v':       /* --version */
			{
				const char **sp = ipsec_copyright_notice();

				printf("strongSwan "VERSION"%s\n", compile_time_interop_options);
				for (; *sp != NULL; sp++)
					puts(*sp);
			}
			exit_pluto(0);
			break;      /* not actually reached */

		case '+':       /* --optionsfrom <filename> */
			if (!options->from(options, optarg, &argc, &argv, optind))
			{
				exit_pluto(1);
			}
			continue;

		case 'd':       /* --nofork*/
			fork_desired = FALSE;
			continue;

		case 'e':       /* --stderrlog */
			log_to_stderr_desired = TRUE;
			continue;

		case 'n':       /* --noklips */
			no_klips = TRUE;
			continue;

		case 'c':       /* --nocrsend */
			no_cr_send = TRUE;
			continue;

		case 'r':       /* --strictcrlpolicy */
			strict_crl_policy = TRUE;
			continue;

		case 'x':       /* --crlcheckinterval <time>*/
			if (optarg == NULL || !isdigit(optarg[0]))
				usage("missing interval time");

			{
				char *endptr;
				long interval = strtol(optarg, &endptr, 0);

				if (*endptr != '\0' || endptr == optarg
				|| interval <= 0)
					usage("<interval-time> must be a positive number");
				crl_check_interval = interval;
			}
			continue;

		case 'C':       /* --cachecrls */
			cache_crls = TRUE;
			continue;

		case 'u':       /* --uniqueids */
			uniqueIDs = TRUE;
			continue;

		case 'i':       /* --interface <ifname> */
			if (!use_interface(optarg))
				usage("too many --interface specifications");
			continue;

		case 'p':       /* --port <portnumber> */
			if (optarg == NULL || !isdigit(optarg[0]))
				usage("missing port number");

			{
				char *endptr;
				long port = strtol(optarg, &endptr, 0);

				if (*endptr != '\0' || endptr == optarg
				|| port <= 0 || port > 0x10000)
					usage("<port-number> must be a number between 1 and 65535");
				pluto_port = port;
			}
			continue;

		case 'b':       /* --ctlbase <path> */
			if (snprintf(ctl_addr.sun_path, sizeof(ctl_addr.sun_path)
			, "%s%s", optarg, CTL_SUFFIX) == -1)
				usage("<path>" CTL_SUFFIX " too long for sun_path");
			if (snprintf(info_addr.sun_path, sizeof(info_addr.sun_path)
			, "%s%s", optarg, INFO_SUFFIX) == -1)
				usage("<path>" INFO_SUFFIX " too long for sun_path");
			if (snprintf(pluto_lock, sizeof(pluto_lock)
			, "%s%s", optarg, LOCK_SUFFIX) == -1)
				usage("<path>" LOCK_SUFFIX " must fit");
			continue;

		case 's':       /* --secretsfile <secrets-file> */
			shared_secrets_file = optarg;
			continue;

		case 'f':       /* --policygroupsdir <policygroups-dir> */
			policygroups_dir = optarg;
			continue;

		case 'a':       /* --adns <pathname> */
			pluto_adns_option = optarg;
			continue;

		case 'm':       /* --pkcs11module <pathname> */
			pkcs11_module_path = optarg;
			continue;

		case 'k':       /* --pkcs11keepstate */
			pkcs11_keep_state = TRUE;
			continue;

		case 'y':       /* --pkcs11proxy */
			pkcs11_proxy = TRUE;
			continue;

		case 'z':       /* --pkcs11initargs */
			pkcs11_init_args = optarg;
			continue;

#ifdef DEBUG
		case 'N':       /* --debug-none */
			base_debugging = DBG_NONE;
			continue;

		case 'A':       /* --debug-all */
			base_debugging = DBG_ALL;
			continue;
#endif

		case 'P':       /* --perpeerlogbase */
			base_perpeer_logdir = optarg;
			continue;

		case 'l':
			log_to_perpeer = TRUE;
			continue;

		case '1':       /* --nat_traversal */
			nat_traversal = TRUE;
			continue;
		case '2':       /* --keep_alive */
			keep_alive = atoi(optarg);
			continue;
		case '3':       /* --force_keepalive */
			force_keepalive = TRUE;
			continue;
		case '4':       /* --disable_port_floating */
			nat_t_spf = FALSE;
			continue;
		case '5':       /* --debug-nat_t */
			base_debugging |= DBG_NATT;
			continue;
		case '6':       /* --virtual_private */
			virtual_private = optarg;
			continue;

		default:
#ifdef DEBUG
			if (c >= DBG_OFFSET)
			{
				base_debugging |= c - DBG_OFFSET;
				continue;
			}
#       undef DBG_OFFSET
#endif
			bad_case(c);
		}
		break;
	}
	if (optind != argc)
		usage("unexpected argument");
	reset_debugging();
	lockfd = create_lock();

	/* select between logging methods */

	if (log_to_stderr_desired)
	{
		log_to_syslog = FALSE;
	}
	else
	{
		log_to_stderr = FALSE;
	}

	/* set the logging function of pfkey debugging */
#ifdef DEBUG
	pfkey_debug_func = DBG_log;
#else
	pfkey_debug_func = NULL;
#endif

	/* create control socket.
	 * We must create it before the parent process returns so that
	 * there will be no race condition in using it.  The easiest
	 * place to do this is before the daemon fork.
	 */
	{
		err_t ugh = init_ctl_socket();

		if (ugh != NULL)
		{
			fprintf(stderr, "pluto: %s", ugh);
			exit_pluto(1);
		}
	}

	/* If not suppressed, do daemon fork */

	if (fork_desired)
	{
		{
			pid_t pid = fork();

			if (pid < 0)
			{
				int e = errno;

				fprintf(stderr, "pluto: fork failed (%d %s)\n",
					errno, strerror(e));
				exit_pluto(1);
			}

			if (pid != 0)
			{
				/* parent: die, after filling PID into lock file.
				 * must not use exit_pluto: lock would be removed!
				 */
				exit(fill_lock(lockfd, pid)? 0 : 1);
			}
		}

		if (setsid() < 0)
		{
			int e = errno;

			fprintf(stderr, "setsid() failed in main(). Errno %d: %s\n",
				errno, strerror(e));
			exit_pluto(1);
		}
	}
	else
	{
		/* no daemon fork: we have to fill in lock file */
		(void) fill_lock(lockfd, getpid());
		fprintf(stdout, "Pluto initialized\n");
		fflush(stdout);
	}

	/* Close everything but ctl_fd and (if needed) stderr.
	 * There is some danger that a library that we don't know
	 * about is using some fd that we don't know about.
	 * I guess we'll soon find out.
	 */
	{
		int i;

		for (i = getdtablesize() - 1; i >= 0; i--)  /* Bad hack */
		{
			if ((!log_to_stderr || i != 2) && i != ctl_fd)
				close(i);
		}

		/* make sure that stdin, stdout, stderr are reserved */
		if (open("/dev/null", O_RDONLY) != 0)
			abort();
		if (dup2(0, 1) != 1)
			abort();
		if (!log_to_stderr && dup2(0, 2) != 2)
			abort();
	}

	init_constants();
	init_log("pluto");

	/* Note: some scripts may look for this exact message -- don't change
	 * ipsec barf was one, but it no longer does.
	 */
	plog("Starting IKEv1 pluto daemon (strongSwan "VERSION")%s",
		 compile_time_interop_options);

	if (lib->integrity)
	{
		plog("integrity tests enabled:");
		plog("lib    'libstrongswan': passed file and segment integrity tests");
		plog("lib    'libhydra': passed file and segment integrity tests");
		plog("daemon 'pluto': passed file integrity test");
	}

	/* load plugins, further infrastructure may need it */
	if (!lib->plugins->load(lib->plugins, NULL,
			lib->settings->get_str(lib->settings, "pluto.load", PLUGINS)))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	print_plugins();

	init_builder();
	if (!init_secret() || !init_crypto())
	{
		plog("initialization failed - aborting pluto");
		exit_pluto(SS_RC_INITIALIZATION_FAILED);
	}
	init_nat_traversal(nat_traversal, keep_alive, force_keepalive, nat_t_spf);
	init_virtual_ip(virtual_private);
	scx_init(pkcs11_module_path, pkcs11_init_args);
	init_states();
	init_demux();
	init_kernel();
	init_adns();
	init_myid();
	fetch_initialize();
	ac_initialize();
	whack_attribute_initialize();

	/* drop unneeded capabilities and change UID/GID */
	prctl(PR_SET_KEEPCAPS, 1);

#ifdef IPSEC_GROUP
	{
		struct group group, *grp;
	char buf[1024];

		if (getgrnam_r(IPSEC_GROUP, &group, buf, sizeof(buf), &grp) != 0 ||
				grp == NULL || setgid(grp->gr_gid) != 0)
		{
			plog("unable to change daemon group");
			abort();
		}
	}
#endif
#ifdef IPSEC_USER
	{
		struct passwd passwd, *pwp;
	char buf[1024];

		if (getpwnam_r(IPSEC_USER, &passwd, buf, sizeof(buf), &pwp) != 0 ||
				pwp == NULL || setuid(pwp->pw_uid) != 0)
		{
			plog("unable to change daemon user");
			abort();
		}
		}
#endif

#ifdef CAPABILITIES
	caps = cap_init();
	cap_set_flag(caps, CAP_EFFECTIVE, 2, keep, CAP_SET);
	cap_set_flag(caps, CAP_INHERITABLE, 2, keep, CAP_SET);
	cap_set_flag(caps, CAP_PERMITTED, 2, keep, CAP_SET);
	if (cap_set_proc(caps) != 0)
	{
		plog("unable to drop daemon capabilities");
		abort();
	}
	cap_free(caps);
#endif /* CAPABILITIES */

	/* loading X.509 CA certificates */
	load_authcerts("ca", CA_CERT_PATH, X509_CA);
	/* loading X.509 AA certificates */
	load_authcerts("aa", AA_CERT_PATH, X509_AA);
	/* loading X.509 OCSP certificates */
	load_authcerts("ocsp", OCSP_CERT_PATH, X509_OCSP_SIGNER);
	/* loading X.509 CRLs */
	load_crls();
	/* loading attribute certificates (experimental) */
	ac_load_certs();

	daily_log_event();
	call_server();
	return -1;  /* Shouldn't ever reach this */
}

/* leave pluto, with status.
 * Once child is launched, parent must not exit this way because
 * the lock would be released.
 *
 *  0 OK
 *  1 general discomfort
 * 10 lock file exists
 */
void exit_pluto(int status)
{
	reset_globals();    /* needed because we may be called in odd state */
	free_preshared_secrets();
	free_remembered_public_keys();
	delete_every_connection();
	whack_attribute_finalize(); /* free in-memory pools */
	fetch_finalize();           /* stop fetching thread */
	free_crl_fetch();           /* free chain of crl fetch requests */
	free_ocsp_fetch();          /* free chain of ocsp fetch requests */
	free_authcerts();           /* free chain of X.509 authority certificates */
	free_crls();                /* free chain of X.509 CRLs */
	free_ca_infos();            /* free chain of X.509 CA information records */
	free_ocsp();                /* free ocsp cache */
	free_ifaces();
	ac_finalize();              /* free X.509 attribute certificates */
	scx_finalize();             /* finalize and unload PKCS #11 module */
	stop_adns();
	free_md_pool();
	free_crypto();
	free_myid();                /* free myids */
	free_events();              /* free remaining events */
	free_vendorid();            /* free all vendor id records */
	free_builder();
	delete_lock();
	options->destroy(options);
	pluto_deinit();
	lib->plugins->unload(lib->plugins);
	libhydra_deinit();
	library_deinit();
	close_log();
	exit(status);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
