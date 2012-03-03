/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "farp_listener.h"

#include <utils/hashtable.h>
#include <threading/rwlock.h>

typedef struct private_farp_listener_t private_farp_listener_t;

/**
 * Private data of an farp_listener_t object.
 */
struct private_farp_listener_t {

	/**
	 * Public farp_listener_t interface.
	 */
	farp_listener_t public;

	/**
	 * Hashtable with active virtual IPs
	 */
	hashtable_t *ips;

	/**
	 * RWlock for IP list
	 */
	rwlock_t *lock;
};

/**
 * Hashtable hash function
 */
static u_int hash(host_t *key)
{
	return chunk_hash(key->get_address(key));
}

/**
 * Hashtable equals function
 */
static bool equals(host_t *a, host_t *b)
{
	return a->ip_equals(a, b);
}

METHOD(listener_t, ike_updown, bool,
	private_farp_listener_t *this, ike_sa_t *ike_sa, bool up)
{
	if (!up)
	{
		host_t *ip;

		ip = ike_sa->get_virtual_ip(ike_sa, FALSE);
		if (ip)
		{
			this->lock->write_lock(this->lock);
			ip = this->ips->remove(this->ips, ip);
			this->lock->unlock(this->lock);
			DESTROY_IF(ip);
		}
	}
	return TRUE;
}

METHOD(listener_t, message_hook, bool,
	private_farp_listener_t *this, ike_sa_t *ike_sa,
	message_t *message, bool incoming)
{
	if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
		message->get_exchange_type(message) == IKE_AUTH &&
		!message->get_request(message))
	{
		host_t *ip;

		ip = ike_sa->get_virtual_ip(ike_sa, FALSE);
		if (ip)
		{
			ip = ip->clone(ip);
			this->lock->write_lock(this->lock);
			ip = this->ips->put(this->ips, ip, ip);
			this->lock->unlock(this->lock);
			DESTROY_IF(ip);
		}
	}
	return TRUE;
}

METHOD(farp_listener_t, is_active, bool,
	private_farp_listener_t *this, host_t *ip)
{
	bool active;

	this->lock->read_lock(this->lock);
	active = this->ips->get(this->ips, ip) != NULL;
	this->lock->unlock(this->lock);
	return active;
}

METHOD(farp_listener_t, destroy, void,
	private_farp_listener_t *this)
{
	enumerator_t *enumerator;
	host_t *key, *value;

	enumerator = this->ips->create_enumerator(this->ips);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		value->destroy(value);
	}
	enumerator->destroy(enumerator);
	this->ips->destroy(this->ips);

	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
farp_listener_t *farp_listener_create()
{
	private_farp_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_updown = _ike_updown,
				.message = _message_hook,
			},
			.is_active = _is_active,
			.destroy = _destroy,
		},
		.ips = hashtable_create((hashtable_hash_t)hash,
								(hashtable_equals_t)equals, 8),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}

