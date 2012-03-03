/*
 * Copyright (C) 2008 Martin Willi
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

#include "stroke_list.h"

#include <time.h>

#include <daemon.h>
#include <utils/linked_list.h>
#include <credentials/certificates/x509.h>
#include <credentials/certificates/ac.h>
#include <credentials/certificates/crl.h>
#include <credentials/certificates/pgp_certificate.h>
#include <credentials/ietf_attributes/ietf_attributes.h>
#include <config/peer_cfg.h>

/* warning intervals for list functions */
#define CERT_WARNING_INTERVAL  30	/* days */
#define CRL_WARNING_INTERVAL	7	/* days */
#define AC_WARNING_INTERVAL		1	/* day */

typedef struct private_stroke_list_t private_stroke_list_t;

/**
 * private data of stroke_list
 */
struct private_stroke_list_t {

	/**
	 * public functions
	 */
	stroke_list_t public;

	/**
	 * timestamp of daemon start
	 */
	time_t uptime;

	/**
	 * strokes attribute provider
	 */
	stroke_attribute_t *attribute;
};

/**
 * Log tasks of a specific queue to out
 */
static void log_task_q(FILE *out, ike_sa_t *ike_sa, task_queue_t q, char *name)
{
	enumerator_t *enumerator;
	bool has = FALSE;
	task_t *task;

	enumerator = ike_sa->create_task_enumerator(ike_sa, q);
	while (enumerator->enumerate(enumerator, &task))
	{
		if (!has)
		{
			fprintf(out, "%12s[%d]: Tasks %s: ", ike_sa->get_name(ike_sa),
					ike_sa->get_unique_id(ike_sa), name);
			has = TRUE;
		}
		fprintf(out, "%N ", task_type_names, task->get_type(task));
	}
	enumerator->destroy(enumerator);
	if (has)
	{
		fprintf(out, "\n");
	}
}

/**
 * log an IKE_SA to out
 */
static void log_ike_sa(FILE *out, ike_sa_t *ike_sa, bool all)
{
	ike_sa_id_t *id = ike_sa->get_id(ike_sa);
	time_t now = time_monotonic(NULL);

	fprintf(out, "%12s[%d]: %N",
			ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
			ike_sa_state_names, ike_sa->get_state(ike_sa));

	if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED)
	{
		time_t established;

		established = ike_sa->get_statistic(ike_sa, STAT_ESTABLISHED);
		fprintf(out, " %V ago", &now, &established);
	}

	fprintf(out, ", %H[%Y]...%H[%Y]\n",
			ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
			ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));

	if (all)
	{
		proposal_t *ike_proposal;

		ike_proposal = ike_sa->get_proposal(ike_sa);

		fprintf(out, "%12s[%d]: IKE SPIs: %.16llx_i%s %.16llx_r%s",
				ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
				id->get_initiator_spi(id), id->is_initiator(id) ? "*" : "",
				id->get_responder_spi(id), id->is_initiator(id) ? "" : "*");


		if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED)
		{
			time_t rekey, reauth;
			peer_cfg_t *peer_cfg;

			rekey = ike_sa->get_statistic(ike_sa, STAT_REKEY);
			reauth = ike_sa->get_statistic(ike_sa, STAT_REAUTH);
			peer_cfg = ike_sa->get_peer_cfg(ike_sa);

			if (rekey)
			{
				fprintf(out, ", rekeying in %V", &rekey, &now);
			}
			if (reauth)
			{
				bool first = TRUE;
				enumerator_t *enumerator;
				auth_cfg_t *auth;

				fprintf(out, ", ");
				enumerator = peer_cfg->create_auth_cfg_enumerator(peer_cfg, TRUE);
				while (enumerator->enumerate(enumerator, &auth))
				{
					if (!first)
					{
						fprintf(out, "+");
					}
					first = FALSE;
					fprintf(out, "%N", auth_class_names,
							auth->get(auth, AUTH_RULE_AUTH_CLASS));
				}
				enumerator->destroy(enumerator);
				fprintf(out, " reauthentication in %V", &reauth, &now);
			}
			if (!rekey && !reauth)
			{
				fprintf(out, ", rekeying disabled");
			}
		}
		fprintf(out, "\n");

		if (ike_proposal)
		{
			char buf[BUF_LEN];

			snprintf(buf, BUF_LEN, "%P", ike_proposal);
			fprintf(out, "%12s[%d]: IKE proposal: %s\n",
					ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
					buf+4);
		}

		log_task_q(out, ike_sa, TASK_QUEUE_QUEUED, "queued");
		log_task_q(out, ike_sa, TASK_QUEUE_ACTIVE, "active");
		log_task_q(out, ike_sa, TASK_QUEUE_PASSIVE, "passive");
	}
}

/**
 * log an CHILD_SA to out
 */
static void log_child_sa(FILE *out, child_sa_t *child_sa, bool all)
{
	time_t use_in, use_out, rekey, now;
	u_int64_t bytes_in, bytes_out;
	proposal_t *proposal;
	child_cfg_t *config = child_sa->get_config(child_sa);


	fprintf(out, "%12s{%d}:  %N, %N%s",
			child_sa->get_name(child_sa), child_sa->get_reqid(child_sa),
			child_sa_state_names, child_sa->get_state(child_sa),
			ipsec_mode_names, child_sa->get_mode(child_sa),
			config->use_proxy_mode(config) ? "_PROXY" : "");

	if (child_sa->get_state(child_sa) == CHILD_INSTALLED)
	{
		fprintf(out, ", %N%s SPIs: %.8x_i %.8x_o",
				protocol_id_names, child_sa->get_protocol(child_sa),
				child_sa->has_encap(child_sa) ? " in UDP" : "",
				ntohl(child_sa->get_spi(child_sa, TRUE)),
				ntohl(child_sa->get_spi(child_sa, FALSE)));

		if (child_sa->get_ipcomp(child_sa) != IPCOMP_NONE)
		{
			fprintf(out, ", IPCOMP CPIs: %.4x_i %.4x_o",
					ntohs(child_sa->get_cpi(child_sa, TRUE)),
					ntohs(child_sa->get_cpi(child_sa, FALSE)));
		}

		if (all)
		{
			fprintf(out, "\n%12s{%d}:  ", child_sa->get_name(child_sa),
					child_sa->get_reqid(child_sa));

			proposal = child_sa->get_proposal(child_sa);
			if (proposal)
			{
				u_int16_t encr_alg = ENCR_UNDEFINED, int_alg = AUTH_UNDEFINED;
				u_int16_t encr_size = 0, int_size = 0;

				proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM,
										&encr_alg, &encr_size);
				proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM,
										&int_alg, &int_size);

				if (encr_alg != ENCR_UNDEFINED)
				{
					fprintf(out, "%N", encryption_algorithm_names, encr_alg);
					if (encr_size)
					{
						fprintf(out, "_%u", encr_size);
					}
				}
				if (int_alg != AUTH_UNDEFINED)
				{
					fprintf(out, "/%N", integrity_algorithm_names, int_alg);
					if (int_size)
					{
						fprintf(out, "_%u", int_size);
					}
				}
			}

			now = time_monotonic(NULL);
			child_sa->get_usestats(child_sa, TRUE, &use_in, &bytes_in);
			fprintf(out, ", %llu bytes_i", bytes_in);
			if (use_in)
			{
				fprintf(out, " (%ds ago)", now - use_in);
			}

			child_sa->get_usestats(child_sa, FALSE, &use_out, &bytes_out);
			fprintf(out, ", %llu bytes_o", bytes_out);
			if (use_out)
			{
				fprintf(out, " (%ds ago)", now - use_out);
			}
			fprintf(out, ", rekeying ");

			rekey = child_sa->get_lifetime(child_sa, FALSE);
			if (rekey)
			{
				if (now > rekey)
				{
					fprintf(out, "active");
				}
				else
				{
					fprintf(out, "in %V", &now, &rekey);
				}
			}
			else
			{
				fprintf(out, "disabled");
			}

		}
	}

	fprintf(out, "\n%12s{%d}:   %#R=== %#R\n",
			child_sa->get_name(child_sa), child_sa->get_reqid(child_sa),
			child_sa->get_traffic_selectors(child_sa, TRUE),
			child_sa->get_traffic_selectors(child_sa, FALSE));
}

/**
 * Log a configs local or remote authentication config to out
 */
static void log_auth_cfgs(FILE *out, peer_cfg_t *peer_cfg, bool local)
{
	enumerator_t *enumerator, *rules;
	auth_rule_t rule;
	auth_cfg_t *auth;
	auth_class_t auth_class;
	identification_t *id;
	certificate_t *cert;
	cert_validation_t valid;
	char *name;

	name = peer_cfg->get_name(peer_cfg);

	enumerator = peer_cfg->create_auth_cfg_enumerator(peer_cfg, local);
	while (enumerator->enumerate(enumerator, &auth))
	{
		fprintf(out, "%12s:   %s [%Y] uses ", name,	local ? "local: " : "remote:",
				auth->get(auth, AUTH_RULE_IDENTITY));

		auth_class = (uintptr_t)auth->get(auth, AUTH_RULE_AUTH_CLASS);
		if (auth_class != AUTH_CLASS_EAP)
		{
			fprintf(out, "%N authentication\n", auth_class_names, auth_class);
		}
		else
		{
			if ((uintptr_t)auth->get(auth, AUTH_RULE_EAP_TYPE) == EAP_NAK)
			{
				fprintf(out, "EAP authentication");
			}
			else
			{
				if ((uintptr_t)auth->get(auth, AUTH_RULE_EAP_VENDOR))
				{
					fprintf(out, "EAP_%d-%d authentication",
						(uintptr_t)auth->get(auth, AUTH_RULE_EAP_TYPE),
						(uintptr_t)auth->get(auth, AUTH_RULE_EAP_VENDOR));
				}
				else
				{
					fprintf(out, "%N authentication", eap_type_names,
						(uintptr_t)auth->get(auth, AUTH_RULE_EAP_TYPE));
				}
			}
			id = auth->get(auth, AUTH_RULE_EAP_IDENTITY);
			if (id)
			{
				fprintf(out, " with EAP identity '%Y'", id);
			}
			fprintf(out, "\n");
		}

		cert = auth->get(auth, AUTH_RULE_CA_CERT);
		if (cert)
		{
			fprintf(out, "%12s:    ca:    \"%Y\"\n", name, cert->get_subject(cert));
		}

		cert = auth->get(auth, AUTH_RULE_IM_CERT);
		if (cert)
		{
			fprintf(out, "%12s:    im-ca: \"%Y\"\n", name, cert->get_subject(cert));
		}

		cert = auth->get(auth, AUTH_RULE_SUBJECT_CERT);
		if (cert)
		{
			fprintf(out, "%12s:    cert:  \"%Y\"\n", name,
					cert->get_subject(cert));
		}

		valid = (uintptr_t)auth->get(auth, AUTH_RULE_OCSP_VALIDATION);
		if (valid != VALIDATION_FAILED)
		{
			fprintf(out, "%12s:    ocsp:  status must be GOOD%s\n", name,
					(valid == VALIDATION_SKIPPED) ? " or SKIPPED" : "");
		}

		valid = (uintptr_t)auth->get(auth, AUTH_RULE_CRL_VALIDATION);
		if (valid != VALIDATION_FAILED)
		{
			fprintf(out, "%12s:    crl:   status must be GOOD%s\n", name,
					(valid == VALIDATION_SKIPPED) ? " or SKIPPED" : "");
		}

		rules = auth->create_enumerator(auth);
		while (rules->enumerate(rules, &rule, &id))
		{
			if (rule == AUTH_RULE_AC_GROUP)
			{
				fprintf(out, "%12s:    group: %Y\n", name, id);
			}
		}
		rules->destroy(rules);
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of stroke_list_t.status.
 */
static void status(private_stroke_list_t *this, stroke_msg_t *msg, FILE *out, bool all)
{
	enumerator_t *enumerator, *children;
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	child_sa_t *child_sa;
	ike_sa_t *ike_sa;
	bool first, found = FALSE;
	char *name = msg->status.name;

	if (all)
	{
		peer_cfg_t *peer_cfg;
		char *plugin, *pool;
		host_t *host;
		u_int32_t dpd;
		time_t since, now;
		u_int size, online, offline;

		now = time_monotonic(NULL);
		since = time(NULL) - (now - this->uptime);

		fprintf(out, "Status of IKEv2 charon daemon (strongSwan "VERSION"):\n");
		fprintf(out, "  uptime: %V, since %T\n", &now, &this->uptime, &since, FALSE);
		fprintf(out, "  worker threads: %d idle of %d,",
				charon->processor->get_idle_threads(charon->processor),
				charon->processor->get_total_threads(charon->processor));
		fprintf(out, " job queue load: %d,",
				charon->processor->get_job_load(charon->processor));
		fprintf(out, " scheduled events: %d\n",
				charon->scheduler->get_job_load(charon->scheduler));
		fprintf(out, "  loaded plugins: ");
		enumerator = lib->plugins->create_plugin_enumerator(lib->plugins);
		while (enumerator->enumerate(enumerator, &plugin))
		{
			fprintf(out, "%s ", plugin);
		}
		enumerator->destroy(enumerator);
		fprintf(out, "\n");

		first = TRUE;
		enumerator = this->attribute->create_pool_enumerator(this->attribute);
		while (enumerator->enumerate(enumerator, &pool, &size, &online, &offline))
		{
			if (name && !streq(name, pool))
			{
				continue;
			}
			if (first)
			{
				first = FALSE;
				fprintf(out, "Virtual IP pools (size/online/offline):\n");
			}
			fprintf(out, "  %s: %u/%u/%u\n", pool, size, online, offline);
		}
		enumerator->destroy(enumerator);

		enumerator = charon->kernel_interface->create_address_enumerator(
								charon->kernel_interface, FALSE, FALSE);
		fprintf(out, "Listening IP addresses:\n");
		while (enumerator->enumerate(enumerator, (void**)&host))
		{
			fprintf(out, "  %H\n", host);
		}
		enumerator->destroy(enumerator);

		fprintf(out, "Connections:\n");
		enumerator = charon->backends->create_peer_cfg_enumerator(
									charon->backends, NULL, NULL, NULL, NULL);
		while (enumerator->enumerate(enumerator, &peer_cfg))
		{
			if (peer_cfg->get_ike_version(peer_cfg) != 2 ||
				(name && !streq(name, peer_cfg->get_name(peer_cfg))))
			{
				continue;
			}

			ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
			fprintf(out, "%12s:  %s...%s", peer_cfg->get_name(peer_cfg),
				ike_cfg->get_my_addr(ike_cfg), ike_cfg->get_other_addr(ike_cfg));

			dpd = peer_cfg->get_dpd(peer_cfg);
			if (dpd)
			{
				fprintf(out, ", dpddelay=%us", dpd);
			}
			fprintf(out, "\n");

			log_auth_cfgs(out, peer_cfg, TRUE);
			log_auth_cfgs(out, peer_cfg, FALSE);

			children = peer_cfg->create_child_cfg_enumerator(peer_cfg);
			while (children->enumerate(children, &child_cfg))
			{
				linked_list_t *my_ts, *other_ts;

				my_ts = child_cfg->get_traffic_selectors(child_cfg, TRUE, NULL, NULL);
				other_ts = child_cfg->get_traffic_selectors(child_cfg, FALSE, NULL, NULL);
				fprintf(out, "%12s:   child:  %#R=== %#R", child_cfg->get_name(child_cfg),
						my_ts, other_ts);
				my_ts->destroy_offset(my_ts, offsetof(traffic_selector_t, destroy));
				other_ts->destroy_offset(other_ts, offsetof(traffic_selector_t, destroy));

				if (dpd)
				{
					fprintf(out, ", dpdaction=%N", action_names,
							child_cfg->get_dpd_action(child_cfg));
				}
				fprintf(out, "\n");
			}
			children->destroy(children);
		}
		enumerator->destroy(enumerator);
	}

	first = TRUE;
	enumerator = charon->traps->create_enumerator(charon->traps);
	while (enumerator->enumerate(enumerator, NULL, &child_sa))
	{
		if (first)
		{
			fprintf(out, "Routed Connections:\n");
			first = FALSE;
		}
		log_child_sa(out, child_sa, all);
	}
	enumerator->destroy(enumerator);

	fprintf(out, "Security Associations:\n");
	enumerator = charon->controller->create_ike_sa_enumerator(charon->controller);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		bool ike_printed = FALSE;
		iterator_t *children = ike_sa->create_child_sa_iterator(ike_sa);

		if (name == NULL || streq(name, ike_sa->get_name(ike_sa)))
		{
			log_ike_sa(out, ike_sa, all);
			found = TRUE;
			ike_printed = TRUE;
		}

		while (children->iterate(children, (void**)&child_sa))
		{
			if (name == NULL || streq(name, child_sa->get_name(child_sa)))
			{
				if (!ike_printed)
				{
					log_ike_sa(out, ike_sa, all);
					found = TRUE;
					ike_printed = TRUE;
				}
				log_child_sa(out, child_sa, all);
			}
		}
		children->destroy(children);
	}
	enumerator->destroy(enumerator);

	if (!found)
	{
		if (name)
		{
			fprintf(out, "  no match\n");
		}
		else
		{
			fprintf(out, "  none\n");
		}
	}
}

/**
 * create a unique certificate list without duplicates
 * certicates having the same issuer are grouped together.
 */
static linked_list_t* create_unique_cert_list(certificate_type_t type)
{
	linked_list_t *list = linked_list_create();
	enumerator_t *enumerator = charon->credentials->create_cert_enumerator(
									charon->credentials, type, KEY_ANY,
									NULL, FALSE);
	certificate_t *cert;

	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		iterator_t *iterator = list->create_iterator(list, TRUE);
		identification_t *issuer = cert->get_issuer(cert);
		bool previous_same, same = FALSE, last = TRUE;
		certificate_t *list_cert;

		while (iterator->iterate(iterator, (void**)&list_cert))
		{
			/* exit if we have a duplicate? */
			if (list_cert->equals(list_cert, cert))
			{
				last = FALSE;
				break;
			}
			/* group certificates with same issuer */
			previous_same = same;
			same = list_cert->has_issuer(list_cert, issuer);
			if (previous_same && !same)
			{
				iterator->insert_before(iterator, (void *)cert->get_ref(cert));
				last = FALSE;
				break;
			}
		}
		iterator->destroy(iterator);

		if (last)
		{
			list->insert_last(list, (void *)cert->get_ref(cert));
		}
	}
	enumerator->destroy(enumerator);
	return list;
}

/**
 * Print a single public key.
 */
static void list_public_key(public_key_t *public, FILE *out)
{
	private_key_t *private = NULL;
	chunk_t keyid;
	identification_t *id;
	auth_cfg_t *auth;

	if (public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &keyid))
	{
		id = identification_create_from_encoding(ID_KEY_ID, keyid);
		auth = auth_cfg_create();
		private = charon->credentials->get_private(charon->credentials,
									public->get_type(public), id, auth);
		auth->destroy(auth);
		id->destroy(id);
	}

	fprintf(out, "  pubkey:    %N %d bits%s\n",
			key_type_names, public->get_type(public),
			public->get_keysize(public) * 8,
			private ? ", has private key" : "");
	if (public->get_fingerprint(public, KEY_ID_PUBKEY_INFO_SHA1, &keyid))
	{
		fprintf(out, "  keyid:     %#B\n", &keyid);
	}
	if (public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &keyid))
	{
		fprintf(out, "  subjkey:   %#B\n", &keyid);
	}
	DESTROY_IF(private);
}

/**
 * list all raw public keys
 */
static void stroke_list_pubkeys(linked_list_t *list, bool utc, FILE *out)
{
	bool first = TRUE;

	enumerator_t *enumerator = list->create_enumerator(list);
	certificate_t *cert;

	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		public_key_t *public = cert->get_public_key(cert);

		if (public)
		{
			if (first)
			{
				fprintf(out, "\n");
				fprintf(out, "List of Raw Public Keys:\n");
				first = FALSE;
			}
			fprintf(out, "\n");

			list_public_key(public, out);
			public->destroy(public);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list OpenPGP certificates
 */
static void stroke_list_pgp(linked_list_t *list,bool utc, FILE *out)
{
	bool first = TRUE;
	time_t now = time(NULL);
	enumerator_t *enumerator = list->create_enumerator(list);
	certificate_t *cert;

	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		time_t created, until;
		public_key_t *public;
		pgp_certificate_t *pgp_cert = (pgp_certificate_t*)cert;
		chunk_t fingerprint = pgp_cert->get_fingerprint(pgp_cert);

		if (first)
		{

			fprintf(out, "\n");
				fprintf(out, "List of PGP End Entity Certificates:\n");
				first = FALSE;
		}
		fprintf(out, "\n");
		fprintf(out, "  userid:   '%Y'\n", cert->get_subject(cert));

		fprintf(out, "  digest:    %#B\n", &fingerprint);

		/* list validity */
		cert->get_validity(cert, &now, &created, &until);
		fprintf(out, "  created:   %T\n", &created, utc);
		fprintf(out, "  until:     %T%s\n", &until, utc,
			(until == TIME_32_BIT_SIGNED_MAX) ? " (expires never)":"");

		public = cert->get_public_key(cert);
		if (public)
		{
			list_public_key(public, out);
			public->destroy(public);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list all X.509 certificates matching the flags
 */
static void stroke_list_certs(linked_list_t *list, char *label,
							  x509_flag_t flags, bool utc, FILE *out)
{
	bool first = TRUE;
	time_t now = time(NULL);
	enumerator_t *enumerator;
	certificate_t *cert;
	x509_flag_t flag_mask;

	/* mask all auxiliary flags */
	flag_mask = ~(X509_SERVER_AUTH | X509_CLIENT_AUTH |
				  X509_SELF_SIGNED | X509_IP_ADDR_BLOCKS );

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		x509_t *x509 = (x509_t*)cert;
		x509_flag_t x509_flags = x509->get_flags(x509) & flag_mask;

		/* list only if flag is set or flag == 0 */
		if ((x509_flags & flags) || (x509_flags == flags))
		{
			enumerator_t *enumerator;
			identification_t *altName;
			bool first_altName = TRUE;
			int pathlen;
			chunk_t serial, authkey;
			time_t notBefore, notAfter;
			public_key_t *public;

			if (first)
			{
				fprintf(out, "\n");
				fprintf(out, "List of %s:\n", label);
				first = FALSE;
			}
			fprintf(out, "\n");

			/* list subjectAltNames */
			enumerator = x509->create_subjectAltName_enumerator(x509);
			while (enumerator->enumerate(enumerator, (void**)&altName))
			{
				if (first_altName)
				{
					fprintf(out, "  altNames:  ");
					first_altName = FALSE;
				}
				else
				{
					fprintf(out, ", ");
				}
				fprintf(out, "%Y", altName);
			}
			if (!first_altName)
			{
				fprintf(out, "\n");
			}
			enumerator->destroy(enumerator);

			fprintf(out, "  subject:  \"%Y\"\n", cert->get_subject(cert));
			fprintf(out, "  issuer:   \"%Y\"\n", cert->get_issuer(cert));
			serial = x509->get_serial(x509);
			fprintf(out, "  serial:    %#B\n", &serial);

			/* list validity */
			cert->get_validity(cert, &now, &notBefore, &notAfter);
			fprintf(out, "  validity:  not before %T, ", &notBefore, utc);
			if (now < notBefore)
			{
				fprintf(out, "not valid yet (valid in %V)\n", &now, &notBefore);
			}
			else
			{
				fprintf(out, "ok\n");
			}
			fprintf(out, "             not after  %T, ", &notAfter, utc);
			if (now > notAfter)
			{
				fprintf(out, "expired (%V ago)\n", &now, &notAfter);
			}
			else
			{
				fprintf(out, "ok");
				if (now > notAfter - CERT_WARNING_INTERVAL * 60 * 60 * 24)
				{
					fprintf(out, " (expires in %V)", &now, &notAfter);
				}
				fprintf(out, " \n");
			}

			public = cert->get_public_key(cert);
			if (public)
			{
				list_public_key(public, out);
				public->destroy(public);
			}

			/* list optional authorityKeyIdentifier */
			authkey = x509->get_authKeyIdentifier(x509);
			if (authkey.ptr)
			{
				fprintf(out, "  authkey:   %#B\n", &authkey);
			}

			/* list optional pathLenConstraint */
			pathlen = x509->get_pathLenConstraint(x509);
			if (pathlen != X509_NO_PATH_LEN_CONSTRAINT)
			{
				fprintf(out, "  pathlen:   %d\n", pathlen);
			}

			/* list optional ipAddrBlocks */
			if (x509->get_flags(x509) & X509_IP_ADDR_BLOCKS)
			{
				traffic_selector_t *ipAddrBlock;
				bool first_ipAddrBlock = TRUE;

				fprintf(out, "  addresses: ");
				enumerator = x509->create_ipAddrBlock_enumerator(x509);
				while (enumerator->enumerate(enumerator, &ipAddrBlock))
				{
					if (first_ipAddrBlock)
					{
						first_ipAddrBlock = FALSE;
					}
					else
					{
						fprintf(out, ", ");
					}
					fprintf(out, "%R", ipAddrBlock);
				}
				enumerator->destroy(enumerator);
				fprintf(out, "\n");
			}
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list all X.509 attribute certificates
 */
static void stroke_list_acerts(linked_list_t *list, bool utc, FILE *out)
{
	bool first = TRUE;
	time_t thisUpdate, nextUpdate, now = time(NULL);
	enumerator_t *enumerator = list->create_enumerator(list);
	certificate_t *cert;

	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		ac_t *ac = (ac_t*)cert;
		identification_t *id;
		ietf_attributes_t *groups;
		chunk_t chunk;

		if (first)
		{
			fprintf(out, "\n");
			fprintf(out, "List of X.509 Attribute Certificates:\n");
			first = FALSE;
		}
		fprintf(out, "\n");

		id = cert->get_subject(cert);
		if (id)
		{
			fprintf(out, "  holder:   \"%Y\"\n", id);
		}
		id = ac->get_holderIssuer(ac);
		if (id)
		{
			fprintf(out, "  hissuer:  \"%Y\"\n", id);
		}
		chunk = ac->get_holderSerial(ac);
		if (chunk.ptr)
		{
			fprintf(out, "  hserial:   %#B\n", &chunk);
		}
		groups = ac->get_groups(ac);
		if (groups)
		{
			fprintf(out, "  groups:    %s\n", groups->get_string(groups));
			groups->destroy(groups);
		}
		fprintf(out, "  issuer:   \"%Y\"\n", cert->get_issuer(cert));
		chunk  = ac->get_serial(ac);
		fprintf(out, "  serial:    %#B\n", &chunk);

		/* list validity */
		cert->get_validity(cert, &now, &thisUpdate, &nextUpdate);
		fprintf(out, "  updates:   this %T\n",  &thisUpdate, utc);
		fprintf(out, "             next %T, ", &nextUpdate, utc);
		if (now > nextUpdate)
		{
			fprintf(out, "expired (%V ago)\n", &now, &nextUpdate);
		}
		else
		{
			fprintf(out, "ok");
			if (now > nextUpdate - AC_WARNING_INTERVAL * 60 * 60 * 24)
			{
				fprintf(out, " (expires in %V)", &now, &nextUpdate);
			}
			fprintf(out, " \n");
		}

		/* list optional authorityKeyIdentifier */
		chunk = ac->get_authKeyIdentifier(ac);
		if (chunk.ptr)
		{
			fprintf(out, "  authkey:   %#B\n", &chunk);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list all X.509 CRLs
 */
static void stroke_list_crls(linked_list_t *list, bool utc, FILE *out)
{
	bool first = TRUE;
	time_t thisUpdate, nextUpdate, now = time(NULL);
	enumerator_t *enumerator = list->create_enumerator(list);
	certificate_t *cert;

	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		crl_t *crl = (crl_t*)cert;
		chunk_t chunk;

		if (first)
		{
			fprintf(out, "\n");
			fprintf(out, "List of X.509 CRLs:\n");
			first = FALSE;
		}
		fprintf(out, "\n");

		fprintf(out, "  issuer:   \"%Y\"\n", cert->get_issuer(cert));

		/* list optional crlNumber */
		chunk = crl->get_serial(crl);
		if (chunk.ptr)
		{
			fprintf(out, "  serial:    %#B\n", &chunk);
		}

		/* count the number of revoked certificates */
		{
			int count = 0;
			enumerator_t *enumerator = crl->create_enumerator(crl);

			while (enumerator->enumerate(enumerator, NULL, NULL, NULL))
			{
				count++;
			}
			fprintf(out, "  revoked:   %d certificate%s\n", count,
							(count == 1)? "" : "s");
			enumerator->destroy(enumerator);
		}

		/* list validity */
		cert->get_validity(cert, &now, &thisUpdate, &nextUpdate);
		fprintf(out, "  updates:   this %T\n",  &thisUpdate, utc);
		fprintf(out, "             next %T, ", &nextUpdate, utc);
		if (now > nextUpdate)
		{
			fprintf(out, "expired (%V ago)\n", &now, &nextUpdate);
		}
		else
		{
			fprintf(out, "ok");
			if (now > nextUpdate - CRL_WARNING_INTERVAL * 60 * 60 * 24)
			{
				fprintf(out, " (expires in %V)", &now, &nextUpdate);
			}
			fprintf(out, " \n");
		}

		/* list optional authorityKeyIdentifier */
		chunk = crl->get_authKeyIdentifier(crl);
		if (chunk.ptr)
		{
			fprintf(out, "  authkey:   %#B\n", &chunk);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list all OCSP responses
 */
static void stroke_list_ocsp(linked_list_t* list, bool utc, FILE *out)
{
	bool first = TRUE;
	enumerator_t *enumerator = list->create_enumerator(list);
	certificate_t *cert;

	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		if (first)
		{
			fprintf(out, "\n");
			fprintf(out, "List of OCSP responses:\n");
			fprintf(out, "\n");
			first = FALSE;
		}

		fprintf(out, "  signer:   \"%Y\"\n", cert->get_issuer(cert));
	}
	enumerator->destroy(enumerator);
}

/**
 * List of registered cryptographical algorithms
 */
static void list_algs(FILE *out)
{
	enumerator_t *enumerator;
	encryption_algorithm_t encryption;
	integrity_algorithm_t integrity;
	hash_algorithm_t hash;
	pseudo_random_function_t prf;
	diffie_hellman_group_t group;

	fprintf(out, "\n");
	fprintf(out, "List of registered IKEv2 Algorithms:\n");
	fprintf(out, "\n  encryption: ");
	enumerator = lib->crypto->create_crypter_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &encryption))
	{
		fprintf(out, "%N ", encryption_algorithm_names, encryption);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n  integrity:  ");
	enumerator = lib->crypto->create_signer_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &integrity))
	{
		fprintf(out, "%N ", integrity_algorithm_names, integrity);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n  hasher:     ");
	enumerator = lib->crypto->create_hasher_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &hash))
	{
		fprintf(out, "%N ", hash_algorithm_names, hash);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n  prf:        ");
	enumerator = lib->crypto->create_prf_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &prf))
	{
		fprintf(out, "%N ", pseudo_random_function_names, prf);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n  dh-group:   ");
	enumerator = lib->crypto->create_dh_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &group))
	{
		fprintf(out, "%N ", diffie_hellman_group_names, group);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n");
}

/**
 * Implementation of stroke_list_t.list.
 */
static void list(private_stroke_list_t *this, stroke_msg_t *msg, FILE *out)
{
	linked_list_t *cert_list = NULL;

	if (msg->list.flags & LIST_PUBKEYS)
	{
		linked_list_t *pubkey_list = create_unique_cert_list(CERT_TRUSTED_PUBKEY);

		stroke_list_pubkeys(pubkey_list, msg->list.utc, out);
		pubkey_list->destroy_offset(pubkey_list, offsetof(certificate_t, destroy));
	}
	if (msg->list.flags & LIST_CERTS)
	{
		linked_list_t *pgp_list = create_unique_cert_list(CERT_GPG);

		stroke_list_pgp(pgp_list, msg->list.utc, out);
		pgp_list->destroy_offset(pgp_list, offsetof(certificate_t, destroy));
	}
	if (msg->list.flags & (LIST_CERTS | LIST_CACERTS | LIST_OCSPCERTS | LIST_AACERTS))
	{
		cert_list = create_unique_cert_list(CERT_X509);
	}
	if (msg->list.flags & LIST_CERTS)
	{
		stroke_list_certs(cert_list, "X.509 End Entity Certificates",
						  X509_NONE, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_CACERTS)
	{
		stroke_list_certs(cert_list, "X.509 CA Certificates",
						  X509_CA, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_OCSPCERTS)
	{
		stroke_list_certs(cert_list, "X.509 OCSP Signer Certificates",
						  X509_OCSP_SIGNER, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_AACERTS)
	{
		stroke_list_certs(cert_list, "X.509 AA Certificates",
						  X509_AA, msg->list.utc, out);
	}
	DESTROY_OFFSET_IF(cert_list, offsetof(certificate_t, destroy));

	if (msg->list.flags & LIST_ACERTS)
	{
		linked_list_t *ac_list = create_unique_cert_list(CERT_X509_AC);

		stroke_list_acerts(ac_list, msg->list.utc, out);
		ac_list->destroy_offset(ac_list, offsetof(certificate_t, destroy));
	}
	if (msg->list.flags & LIST_CRLS)
	{
		linked_list_t *crl_list = create_unique_cert_list(CERT_X509_CRL);

		stroke_list_crls(crl_list, msg->list.utc, out);
		crl_list->destroy_offset(crl_list, offsetof(certificate_t, destroy));
	}
	if (msg->list.flags & LIST_OCSP)
	{
		linked_list_t *ocsp_list = create_unique_cert_list(CERT_X509_OCSP_RESPONSE);

		stroke_list_ocsp(ocsp_list, msg->list.utc, out);

		ocsp_list->destroy_offset(ocsp_list, offsetof(certificate_t, destroy));
	}
	if (msg->list.flags & LIST_ALGS)
	{
		list_algs(out);
	}
}

/**
 * Print leases of a single pool
 */
static void pool_leases(private_stroke_list_t *this, FILE *out, char *pool,
						host_t *address, u_int size, u_int online, u_int offline)
{
	enumerator_t *enumerator;
	identification_t *id;
	host_t *lease;
	bool on;
	int found = 0;

	fprintf(out, "Leases in pool '%s', usage: %lu/%lu, %lu online\n",
			pool, online + offline, size, online);
	enumerator = this->attribute->create_lease_enumerator(this->attribute, pool);
	while (enumerator && enumerator->enumerate(enumerator, &id, &lease, &on))
	{
		if (!address || address->ip_equals(address, lease))
		{
			fprintf(out, "  %15H   %s   '%Y'\n",
					lease, on ? "online" : "offline", id);
			found++;
		}
	}
	enumerator->destroy(enumerator);
	if (!found)
	{
		fprintf(out, "  no matching leases found\n");
	}
}

/**
 * Implementation of stroke_list_t.leases
 */
static void leases(private_stroke_list_t *this, stroke_msg_t *msg, FILE *out)
{
	enumerator_t *enumerator;
	u_int size, offline, online;
	host_t *address = NULL;
	char *pool;
	int found = 0;

	if (msg->leases.address)
	{
		address = host_create_from_string(msg->leases.address, 0);
	}

	enumerator = this->attribute->create_pool_enumerator(this->attribute);
	while (enumerator->enumerate(enumerator, &pool, &size, &online, &offline))
	{
		if (!msg->leases.pool || streq(msg->leases.pool, pool))
		{
			pool_leases(this, out, pool, address, size, online, offline);
			found++;
		}
	}
	enumerator->destroy(enumerator);
	if (!found)
	{
		if (msg->leases.pool)
		{
			fprintf(out, "pool '%s' not found\n", msg->leases.pool);
		}
		else
		{
			fprintf(out, "no pools found\n");
		}
	}
	DESTROY_IF(address);
}

/**
 * Implementation of stroke_list_t.destroy
 */
static void destroy(private_stroke_list_t *this)
{
	free(this);
}

/*
 * see header file
 */
stroke_list_t *stroke_list_create(stroke_attribute_t *attribute)
{
	private_stroke_list_t *this = malloc_thing(private_stroke_list_t);

	this->public.list = (void(*)(stroke_list_t*, stroke_msg_t *msg, FILE *out))list;
	this->public.status = (void(*)(stroke_list_t*, stroke_msg_t *msg, FILE *out,bool))status;
	this->public.leases = (void(*)(stroke_list_t*, stroke_msg_t *msg, FILE *out))leases;
	this->public.destroy = (void(*)(stroke_list_t*))destroy;

	this->uptime = time_monotonic(NULL);
	this->attribute = attribute;

	return &this->public;
}

