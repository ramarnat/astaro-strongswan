/*
 * Copyright (C) 2006-2007 Martin Willi
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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

#include "ike_natd.h"

#include <string.h>

#include <daemon.h>
#include <config/peer_cfg.h>
#include <crypto/hashers/hasher.h>
#include <encoding/payloads/notify_payload.h>


typedef struct private_ike_natd_t private_ike_natd_t;

/**
 * Private members of a ike_natd_t task.
 */
struct private_ike_natd_t {

	/**
	 * Public methods and task_t interface.
	 */
	ike_natd_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the initiator?
	 */
	bool initiator;

	/**
	 * Hasher used to build NAT detection hashes
	 */
	hasher_t *hasher;

	/**
	 * Did we process any NAT detection notifys for a source address?
	 */
	bool src_seen;

	/**
	 * Did we process any NAT detection notifys for a destination address?
	 */
	bool dst_seen;

	/**
	 * Have we found a matching source address NAT hash?
	 */
	bool src_matched;

	/**
	 * Have we found a matching destination address NAT hash?
	 */
	bool dst_matched;

	/**
	 * whether NAT mappings for our NATed address has changed
	 */
	bool mapping_changed;
};


/**
 * Build NAT detection hash for a host
 */
static chunk_t generate_natd_hash(private_ike_natd_t *this,
								  ike_sa_id_t *ike_sa_id, host_t *host)
{
	chunk_t natd_chunk, spi_i_chunk, spi_r_chunk, addr_chunk, port_chunk;
	chunk_t natd_hash;
	u_int64_t spi_i, spi_r;
	u_int16_t port;

	/* prepare all required chunks */
	spi_i = ike_sa_id->get_initiator_spi(ike_sa_id);
	spi_r = ike_sa_id->get_responder_spi(ike_sa_id);
	spi_i_chunk.ptr = (void*)&spi_i;
	spi_i_chunk.len = sizeof(spi_i);
	spi_r_chunk.ptr = (void*)&spi_r;
	spi_r_chunk.len = sizeof(spi_r);
	port = htons(host->get_port(host));
	port_chunk.ptr = (void*)&port;
	port_chunk.len = sizeof(port);
	addr_chunk = host->get_address(host);

	/*  natd_hash = SHA1( spi_i | spi_r | address | port ) */
	natd_chunk = chunk_cat("cccc", spi_i_chunk, spi_r_chunk, addr_chunk, port_chunk);
	this->hasher->allocate_hash(this->hasher, natd_chunk, &natd_hash);
	DBG3(DBG_IKE, "natd_chunk %B", &natd_chunk);
	DBG3(DBG_IKE, "natd_hash %B", &natd_hash);

	chunk_free(&natd_chunk);
	return natd_hash;
}

/**
 * build a faked NATD payload to enforce UDP encap
 */
static chunk_t generate_natd_hash_faked(private_ike_natd_t *this)
{
	rng_t *rng;
	chunk_t chunk;

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_IKE, "unable to get random bytes for NATD fake");
		return chunk_empty;
	}
	rng->allocate_bytes(rng, HASH_SIZE_SHA1, &chunk);
	rng->destroy(rng);
	return chunk;
}

/**
 * Build a NAT detection notify payload.
 */
static notify_payload_t *build_natd_payload(private_ike_natd_t *this,
											notify_type_t type, host_t *host)
{
	chunk_t hash;
	notify_payload_t *notify;
	ike_sa_id_t *ike_sa_id;
	ike_cfg_t *config;

	ike_sa_id = this->ike_sa->get_id(this->ike_sa);
	config = this->ike_sa->get_ike_cfg(this->ike_sa);
	if (config->force_encap(config) && type == NAT_DETECTION_SOURCE_IP)
	{
		hash = generate_natd_hash_faked(this);
	}
	else
	{
		hash = generate_natd_hash(this, ike_sa_id, host);
	}
	notify = notify_payload_create();
	notify->set_notify_type(notify, type);
	notify->set_notification_data(notify, hash);
	chunk_free(&hash);

	return notify;
}

/**
 * read notifys from message and evaluate them
 */
static void process_payloads(private_ike_natd_t *this, message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	notify_payload_t *notify;
	chunk_t hash, src_hash, dst_hash;
	ike_sa_id_t *ike_sa_id;
	host_t *me, *other;
	ike_cfg_t *config;

	/* Precompute NAT-D hashes for incoming NAT notify comparison */
	ike_sa_id = message->get_ike_sa_id(message);
	me = message->get_destination(message);
	other = message->get_source(message);
	dst_hash = generate_natd_hash(this, ike_sa_id, me);
	src_hash = generate_natd_hash(this, ike_sa_id, other);

	DBG3(DBG_IKE, "precalculated src_hash %B", &src_hash);
	DBG3(DBG_IKE, "precalculated dst_hash %B", &dst_hash);

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) != NOTIFY)
		{
			continue;
		}
		notify = (notify_payload_t*)payload;
		switch (notify->get_notify_type(notify))
		{
			case NAT_DETECTION_DESTINATION_IP:
			{
				this->dst_seen = TRUE;
				hash = notify->get_notification_data(notify);
				if (!this->dst_matched)
				{
					DBG3(DBG_IKE, "received dst_hash %B", &hash);
					if (chunk_equals(hash, dst_hash))
					{
						this->dst_matched = TRUE;
					}
				}
				/* RFC4555 says we should also compare against IKE_SA_INIT
				 * NATD payloads, but this does not work: We are running
				 * there at port 500, but use 4500 afterwards... */
				if (message->get_exchange_type(message) == INFORMATIONAL &&
					this->initiator && !this->dst_matched)
				{
					this->mapping_changed = this->ike_sa->has_mapping_changed(
															this->ike_sa, hash);
				}
				break;
			}
			case NAT_DETECTION_SOURCE_IP:
			{
				this->src_seen = TRUE;
				if (!this->src_matched)
				{
					hash = notify->get_notification_data(notify);
					DBG3(DBG_IKE, "received src_hash %B", &hash);
					if (chunk_equals(hash, src_hash))
					{
						this->src_matched = TRUE;
					}
				}
				break;
			}
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	chunk_free(&src_hash);
	chunk_free(&dst_hash);

	if (this->src_seen && this->dst_seen)
	{
		this->ike_sa->enable_extension(this->ike_sa, EXT_NATT);

		this->ike_sa->set_condition(this->ike_sa, COND_NAT_HERE,
									!this->dst_matched);
		this->ike_sa->set_condition(this->ike_sa, COND_NAT_THERE,
									!this->src_matched);
		config = this->ike_sa->get_ike_cfg(this->ike_sa);
		if (this->dst_matched && this->src_matched &&
			config->force_encap(config))
		{
			this->ike_sa->set_condition(this->ike_sa, COND_NAT_FAKE, TRUE);
		}
	}
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_natd_t *this, message_t *message)
{
	process_payloads(this, message);

	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		peer_cfg_t *peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);

#ifdef ME
		/* if we are on a mediated connection we have already switched to
		 * port 4500 and the correct destination port is already configured,
		 * therefore we must not switch again */
		if (peer_cfg->get_mediated_by(peer_cfg))
		{
			return SUCCESS;
		}
#endif /* ME */

		if (this->ike_sa->has_condition(this->ike_sa, COND_NAT_ANY) ||
#ifdef ME
			/* if we are on a mediation connection we switch to port 4500 even
			 * if no NAT is detected. */
			peer_cfg->is_mediation(peer_cfg) ||
#endif /* ME */
			/* if peer supports NAT-T, we switch to port 4500 even
			 * if no NAT is detected. MOBIKE requires this. */
			(peer_cfg->use_mobike(peer_cfg) &&
			 this->ike_sa->supports_extension(this->ike_sa, EXT_NATT)))
		{
			host_t *me, *other;

			/* do not switch if we have a custom port from mobike/NAT */
			me = this->ike_sa->get_my_host(this->ike_sa);
			if (me->get_port(me) == IKEV2_UDP_PORT)
			{
				me->set_port(me, IKEV2_NATT_PORT);
			}
			other = this->ike_sa->get_other_host(this->ike_sa);
			if (other->get_port(other) == IKEV2_UDP_PORT)
			{
				other->set_port(other, IKEV2_NATT_PORT);
			}
		}
	}

	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_natd_t *this, message_t *message)
{
	notify_payload_t *notify;
	enumerator_t *enumerator;
	ike_cfg_t *ike_cfg;
	host_t *host;

	if (this->hasher == NULL)
	{
		DBG1(DBG_IKE, "unable to build NATD payloads, SHA1 not supported");
		return NEED_MORE;
	}

	ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);

	/* destination is always set */
	host = message->get_destination(message);
	notify = build_natd_payload(this, NAT_DETECTION_DESTINATION_IP, host);
	message->add_payload(message, (payload_t*)notify);

	/* source may be any, we have 3 possibilities to get our source address:
	 * 1. It is defined in the config => use the one of the IKE_SA
	 * 2. We do a routing lookup in the kernel interface
	 * 3. Include all possbile addresses
	 */
	host = message->get_source(message);
	if (!host->is_anyaddr(host))
	{	/* 1. */
		notify = build_natd_payload(this, NAT_DETECTION_SOURCE_IP, host);
		message->add_payload(message, (payload_t*)notify);
	}
	else
	{
		host = charon->kernel_interface->get_source_addr(charon->kernel_interface,
							this->ike_sa->get_other_host(this->ike_sa), NULL);
		if (host)
		{	/* 2. */
			host->set_port(host, ike_cfg->get_my_port(ike_cfg));
			notify = build_natd_payload(this, NAT_DETECTION_SOURCE_IP, host);
			message->add_payload(message, (payload_t*)notify);
			host->destroy(host);
		}
		else
		{	/* 3. */
			enumerator = charon->kernel_interface->create_address_enumerator(
										charon->kernel_interface, FALSE, FALSE);
			while (enumerator->enumerate(enumerator, (void**)&host))
			{
				/* apply port 500 to host, but work on a copy */
				host = host->clone(host);
				host->set_port(host, ike_cfg->get_my_port(ike_cfg));
				notify = build_natd_payload(this, NAT_DETECTION_SOURCE_IP, host);
				host->destroy(host);
				message->add_payload(message, (payload_t*)notify);
			}
			enumerator->destroy(enumerator);
		}
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_natd_t *this, message_t *message)
{
	notify_payload_t *notify;
	host_t *me, *other;

	/* only add notifies on successfull responses. */
	if (message->get_exchange_type(message) == IKE_SA_INIT &&
		message->get_payload(message, SECURITY_ASSOCIATION) == NULL)
	{
		return SUCCESS;
	}

	if (this->src_seen && this->dst_seen)
	{
		if (this->hasher == NULL)
		{
			DBG1(DBG_IKE, "unable to build NATD payloads, SHA1 not supported");
			return SUCCESS;
		}

		/* initiator seems to support NAT detection, add response */
		me = message->get_source(message);
		notify = build_natd_payload(this, NAT_DETECTION_SOURCE_IP, me);
		message->add_payload(message, (payload_t*)notify);

		other = message->get_destination(message);
		notify = build_natd_payload(this, NAT_DETECTION_DESTINATION_IP, other);
		message->add_payload(message, (payload_t*)notify);
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_natd_t *this, message_t *message)
{
	process_payloads(this, message);

	return NEED_MORE;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_natd_t *this)
{
	return IKE_NATD;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_natd_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
	this->src_seen = FALSE;
	this->dst_seen = FALSE;
	this->src_matched = FALSE;
	this->dst_matched = FALSE;
	this->mapping_changed = FALSE;
}

/**
 * Implementation of ike_natd_t.has_mapping_changed
 */
static bool has_mapping_changed(private_ike_natd_t *this)
{
	return this->mapping_changed;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_natd_t *this)
{
	DESTROY_IF(this->hasher);
	free(this);
}

/*
 * Described in header.
 */
ike_natd_t *ike_natd_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_natd_t *this = malloc_thing(private_ike_natd_t);

	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;

	if (initiator)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_r;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_r;
	}

	this->public.has_mapping_changed = (bool(*)(ike_natd_t*))has_mapping_changed;

	this->ike_sa = ike_sa;
	this->initiator = initiator;
	this->hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	this->src_seen = FALSE;
	this->dst_seen = FALSE;
	this->src_matched = FALSE;
	this->dst_matched = FALSE;
	this->mapping_changed = FALSE;

	return &this->public;
}
