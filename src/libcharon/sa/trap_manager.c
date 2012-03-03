/*
 * Copyright (C) 2009 Martin Willi
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

#include "trap_manager.h"

#include <daemon.h>
#include <threading/rwlock.h>
#include <utils/linked_list.h>


typedef struct private_trap_manager_t private_trap_manager_t;
typedef struct trap_listener_t trap_listener_t;

/**
 * listener to track acquires
 */
struct trap_listener_t {

	/**
	 * Implements listener interface
	 */
	listener_t listener;

	/**
	 * points to trap_manager
	 */
	private_trap_manager_t *traps;
};

/**
 * Private data of an trap_manager_t object.
 */
struct private_trap_manager_t {

	/**
	 * Public trap_manager_t interface.
	 */
	trap_manager_t public;

	/**
	 * Installed traps, as entry_t
	 */
	linked_list_t *traps;

	/**
	 * read write lock for traps list
	 */
	rwlock_t *lock;

	/**
	 * listener to track acquiring IKE_SAs
	 */
	trap_listener_t listener;
};

/**
 * A installed trap entry
 */
typedef struct {
	/** ref to peer_cfg to initiate */
	peer_cfg_t *peer_cfg;
	/** ref to instanciated CHILD_SA */
	child_sa_t *child_sa;
	/** pending IKE_SA connecting upon acquire */
	ike_sa_t *pending;
} entry_t;

/**
 * actually uninstall and destroy an installed entry
 */
static void destroy_entry(entry_t *entry)
{
	entry->child_sa->destroy(entry->child_sa);
	entry->peer_cfg->destroy(entry->peer_cfg);
	free(entry);
}

/**
 * Implementation of trap_manager_t.install
 */
static u_int32_t install(private_trap_manager_t *this, peer_cfg_t *peer,
					 child_cfg_t *child)
{
	entry_t *entry;
	ike_cfg_t *ike_cfg;
	child_sa_t *child_sa;
	host_t *me, *other;
	linked_list_t *my_ts, *other_ts;
	enumerator_t *enumerator;
	bool found = FALSE;
	status_t status;
	u_int32_t reqid;

	/* check if not already done */
	this->lock->read_lock(this->lock);
	enumerator = this->traps->create_enumerator(this->traps);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (streq(entry->child_sa->get_name(entry->child_sa),
				  child->get_name(child)))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	if (found)
	{
		DBG1(DBG_CFG, "CHILD_SA named '%s' already routed",
			 child->get_name(child));
		return 0;
	}

	/* try to resolve addresses */
	ike_cfg = peer->get_ike_cfg(peer);
	other = host_create_from_dns(ike_cfg->get_other_addr(ike_cfg),
								 0, ike_cfg->get_other_port(ike_cfg));
	if (!other || other->is_anyaddr(other))
	{
		DBG1(DBG_CFG, "installing trap failed, remote address unknown");
		return 0;
	}
	me = host_create_from_dns(ike_cfg->get_my_addr(ike_cfg),
					other->get_family(other), ike_cfg->get_my_port(ike_cfg));
	if (!me || me->is_anyaddr(me))
	{
		DESTROY_IF(me);
		me = charon->kernel_interface->get_source_addr(
									charon->kernel_interface, other, NULL);
		if (!me)
		{
			DBG1(DBG_CFG, "installing trap failed, local address unknown");
			other->destroy(other);
			return 0;
		}
		me->set_port(me, ike_cfg->get_my_port(ike_cfg));
	}

	/* create and route CHILD_SA */
	child_sa = child_sa_create(me, other, child, 0, FALSE);
	my_ts = child->get_traffic_selectors(child, TRUE, NULL, me);
	other_ts = child->get_traffic_selectors(child, FALSE, NULL, other);
	me->destroy(me);
	other->destroy(other);

	/* while we don't know the finally negotiated protocol (ESP|AH), we
	 * could iterate all proposals for a best guest (TODO). But as we
	 * support ESP only for now, we set here. */
	child_sa->set_protocol(child_sa, PROTO_ESP);
	child_sa->set_mode(child_sa, child->get_mode(child));
	status = child_sa->add_policies(child_sa, my_ts, other_ts);
	my_ts->destroy_offset(my_ts, offsetof(traffic_selector_t, destroy));
	other_ts->destroy_offset(other_ts, offsetof(traffic_selector_t, destroy));
	if (status != SUCCESS)
	{
		child_sa->destroy(child_sa);
		DBG1(DBG_CFG, "installing trap failed");
		return 0;
	}

	reqid = child_sa->get_reqid(child_sa);
	entry = malloc_thing(entry_t);
	entry->child_sa = child_sa;
	entry->peer_cfg = peer->get_ref(peer);
	entry->pending = NULL;

	this->lock->write_lock(this->lock);
	this->traps->insert_last(this->traps, entry);
	this->lock->unlock(this->lock);

	return reqid;
}

/**
 * Implementation of trap_manager_t.uninstall
 */
static bool uninstall(private_trap_manager_t *this, u_int32_t reqid)
{
	enumerator_t *enumerator;
	entry_t *entry, *found = NULL;

	this->lock->write_lock(this->lock);
	enumerator = this->traps->create_enumerator(this->traps);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->child_sa->get_reqid(entry->child_sa) == reqid)
		{
			this->traps->remove_at(this->traps, enumerator);
			found = entry;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	if (!found)
	{
		DBG1(DBG_CFG, "trap %d not found to uninstall", reqid);
		return FALSE;
	}

	destroy_entry(found);
	return TRUE;
}

/**
 * convert enumerated entries to peer_cfg, child_sa
 */
static bool trap_filter(rwlock_t *lock, entry_t **entry, peer_cfg_t **peer_cfg,
						void *none, child_sa_t **child_sa)
{
	if (peer_cfg)
	{
		*peer_cfg = (*entry)->peer_cfg;
	}
	if (child_sa)
	{
		*child_sa = (*entry)->child_sa;
	}
	return TRUE;
}

/**
 * Implementation of trap_manager_t.create_enumerator
 */
static enumerator_t* create_enumerator(private_trap_manager_t *this)
{
	this->lock->read_lock(this->lock);
	return enumerator_create_filter(this->traps->create_enumerator(this->traps),
									(void*)trap_filter, this->lock,
									(void*)this->lock->unlock);
}

/**
 * Implementation of trap_manager_t.acquire
 */
static void acquire(private_trap_manager_t *this, u_int32_t reqid,
					traffic_selector_t *src, traffic_selector_t *dst)
{
	enumerator_t *enumerator;
	entry_t *entry, *found = NULL;
	peer_cfg_t *peer;
	child_cfg_t *child;
	ike_sa_t *ike_sa;

	this->lock->read_lock(this->lock);
	enumerator = this->traps->create_enumerator(this->traps);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->child_sa->get_reqid(entry->child_sa) == reqid)
		{
			found = entry;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (!found)
	{
		DBG1(DBG_CFG, "trap not found, unable to acquire reqid %d",reqid);
	}
	else if (found->pending)
	{
		DBG1(DBG_CFG, "ignoring acquire, connection attempt pending");
	}
	else
	{
		child = found->child_sa->get_config(found->child_sa);
		peer = found->peer_cfg;
		ike_sa = charon->ike_sa_manager->checkout_by_config(
												charon->ike_sa_manager, peer);
		if (ike_sa->get_peer_cfg(ike_sa) == NULL)
		{
			ike_sa->set_peer_cfg(ike_sa, peer);
		}
		child->get_ref(child);
		reqid = found->child_sa->get_reqid(found->child_sa);
		if (ike_sa->initiate(ike_sa, child, reqid, src, dst) != DESTROY_ME)
		{
			found->pending = ike_sa;
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		}
		else
		{
			charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, ike_sa);
		}
	}
	this->lock->unlock(this->lock);
}

/**
 * Complete the acquire, if successful or failed
 */
static void complete(private_trap_manager_t *this, ike_sa_t *ike_sa,
					 child_sa_t *child_sa)
{
	enumerator_t *enumerator;
	entry_t *entry;

	this->lock->read_lock(this->lock);
	enumerator = this->traps->create_enumerator(this->traps);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->pending != ike_sa)
		{
			continue;
		}
		if (child_sa && child_sa->get_reqid(child_sa) !=
									entry->child_sa->get_reqid(entry->child_sa))
		{
			continue;
		}
		entry->pending = NULL;
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of listener_t.ike_state_change
 */
static bool ike_state_change(trap_listener_t *listener, ike_sa_t *ike_sa,
							 ike_sa_state_t state)
{
	switch (state)
	{
		case IKE_DESTROYING:
			complete(listener->traps, ike_sa, NULL);
			return TRUE;
		default:
			return TRUE;
	}
}

/**
 * Implementation of listener_t.child_state_change
 */
static bool child_state_change(trap_listener_t *listener, ike_sa_t *ike_sa,
							   child_sa_t *child_sa, child_sa_state_t state)
{
	switch (state)
	{
		case CHILD_INSTALLED:
		case CHILD_DESTROYING:
			complete(listener->traps, ike_sa, child_sa);
			return TRUE;
		default:
			return TRUE;
	}
}

/**
 * Implementation of trap_manager_t.destroy.
 */
static void destroy(private_trap_manager_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->listener.listener);
	this->traps->invoke_function(this->traps, (void*)destroy_entry);
	this->traps->destroy(this->traps);
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
trap_manager_t *trap_manager_create()
{
	private_trap_manager_t *this = malloc_thing(private_trap_manager_t);

	this->public.install = (u_int(*)(trap_manager_t*, peer_cfg_t *peer, child_cfg_t *child))install;
	this->public.uninstall = (bool(*)(trap_manager_t*, u_int32_t id))uninstall;
	this->public.create_enumerator = (enumerator_t*(*)(trap_manager_t*))create_enumerator;
	this->public.acquire = (void(*)(trap_manager_t*, u_int32_t reqid, traffic_selector_t *src, traffic_selector_t *dst))acquire;
	this->public.destroy = (void(*)(trap_manager_t*))destroy;

	this->traps = linked_list_create();
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	/* register listener for IKE state changes */
	this->listener.traps = this;
	memset(&this->listener.listener, 0, sizeof(listener_t));
	this->listener.listener.ike_state_change = (void*)ike_state_change;
	this->listener.listener.child_state_change = (void*)child_state_change;
	charon->bus->add_listener(charon->bus, &this->listener.listener);

	return &this->public;
}

