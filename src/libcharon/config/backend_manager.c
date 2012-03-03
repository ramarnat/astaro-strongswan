/*
 * Copyright (C) 2007-2009 Martin Willi
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

#include "backend_manager.h"

#include <sys/types.h>

#include <daemon.h>
#include <utils/linked_list.h>
#include <threading/rwlock.h>


typedef struct private_backend_manager_t private_backend_manager_t;

/**
 * Private data of an backend_manager_t object.
 */
struct private_backend_manager_t {

	/**
	 * Public part of backend_manager_t object.
	 */
	backend_manager_t public;

	/**
	 * list of registered backends
	 */
	linked_list_t *backends;

	/**
	 * rwlock for backends
	 */
	rwlock_t *lock;
};

/**
 * match of an ike_cfg
 */
typedef enum ike_cfg_match_t {
	MATCH_NONE  = 0x00,
	MATCH_ANY   = 0x01,
	MATCH_ME	= 0x04,
	MATCH_OTHER = 0x08,
} ike_cfg_match_t;

/**
 * data to pass nested IKE enumerator
 */
typedef struct {
	private_backend_manager_t *this;
	host_t *me;
	host_t *other;
} ike_data_t;

/**
 * inner enumerator constructor for IKE cfgs
 */
static enumerator_t *ike_enum_create(backend_t *backend, ike_data_t *data)
{
	return backend->create_ike_cfg_enumerator(backend, data->me, data->other);
}

/**
 * get a match of a candidate ike_cfg for two hosts
 */
static ike_cfg_match_t get_ike_match(ike_cfg_t *cand, host_t *me, host_t *other)
{
	host_t *me_cand, *other_cand;
	ike_cfg_match_t match = MATCH_NONE;

	if (me)
	{
		me_cand = host_create_from_dns(cand->get_my_addr(cand),
									   me->get_family(me), 0);
		if (!me_cand)
		{
			return MATCH_NONE;
		}
		if (me_cand->ip_equals(me_cand, me))
		{
			match += MATCH_ME;
		}
		else if (me_cand->is_anyaddr(me_cand))
		{
			match += MATCH_ANY;
		}
		me_cand->destroy(me_cand);
	}
	else
	{
		match += MATCH_ANY;
	}

	if (other)
	{
		other_cand = host_create_from_dns(cand->get_other_addr(cand),
										  other->get_family(other), 0);
		if (!other_cand)
		{
			return MATCH_NONE;
		}
		if (other_cand->ip_equals(other_cand, other))
		{
			match += MATCH_OTHER;
		}
		else if (other_cand->is_anyaddr(other_cand))
		{
			match += MATCH_ANY;
		}
		other_cand->destroy(other_cand);
	}
	else
	{
		match += MATCH_ANY;
	}
	return match;
}

/**
 * implements backend_manager_t.get_ike_cfg.
 */
static ike_cfg_t *get_ike_cfg(private_backend_manager_t *this,
							  host_t *me, host_t *other)
{
	ike_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;
	ike_cfg_match_t match, best = MATCH_ANY;
	ike_data_t *data;

	data = malloc_thing(ike_data_t);
	data->this = this;
	data->me = me;
	data->other = other;

	DBG2(DBG_CFG, "looking for an ike config for %H...%H", me, other);

	this->lock->read_lock(this->lock);
	enumerator = enumerator_create_nested(
						this->backends->create_enumerator(this->backends),
						(void*)ike_enum_create, data, (void*)free);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		match = get_ike_match(current, me, other);

		if (match)
		{
			DBG2(DBG_CFG, "  candidate: %s...%s, prio %d",
				 current->get_my_addr(current),
				 current->get_other_addr(current), match);
			if (match > best)
			{
				DESTROY_IF(found);
				found = current;
				found->get_ref(found);
				best = match;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	if (found)
	{
		DBG2(DBG_CFG, "found matching ike config: %s...%s with prio %d",
			 found->get_my_addr(found), found->get_other_addr(found), best);
	}
	return found;
}

/**
 * Get the best ID match in one of the configs auth_cfg
 */
static id_match_t get_peer_match(identification_t *id,
								 peer_cfg_t *cfg, bool local)
{
	enumerator_t *enumerator;
	auth_cfg_t *auth;
	identification_t *candidate;
	id_match_t match = ID_MATCH_NONE;

	if (!id)
	{
		return ID_MATCH_ANY;
	}

	/* compare first auth config only */
	enumerator = cfg->create_auth_cfg_enumerator(cfg, local);
	if (enumerator->enumerate(enumerator, &auth))
	{
		candidate = auth->get(auth, AUTH_RULE_IDENTITY);
		if (candidate)
		{
			match = id->matches(id, candidate);
			/* match vice-versa, as the proposed IDr might be ANY */
			if (!match)
			{
				match = candidate->matches(candidate, id);
			}
		}
		else
		{
			match = ID_MATCH_ANY;
		}
	}
	enumerator->destroy(enumerator);
	return match;
}

/**
 * data to pass nested peer enumerator
 */
typedef struct {
	rwlock_t *lock;
	identification_t *me;
	identification_t *other;
} peer_data_t;

/**
 * list element to help sorting
 */
typedef struct {
	id_match_t match_peer;
	ike_cfg_match_t match_ike;
	peer_cfg_t *cfg;
} match_entry_t;

/**
 * inner enumerator constructor for peer cfgs
 */
static enumerator_t *peer_enum_create(backend_t *backend, peer_data_t *data)
{
	return backend->create_peer_cfg_enumerator(backend, data->me, data->other);
}

/**
 * unlock/cleanup peer enumerator
 */
static void peer_enum_destroy(peer_data_t *data)
{
	data->lock->unlock(data->lock);
	free(data);
}

/**
 * convert enumerator value from match_entry to config
 */
static bool peer_enum_filter(linked_list_t *configs,
							 match_entry_t **in, peer_cfg_t **out)
{
	*out = (*in)->cfg;
	return TRUE;
}

/**
 * Clean up temporary config list
 */
static void peer_enum_filter_destroy(linked_list_t *configs)
{
	match_entry_t *entry;

	while (configs->remove_last(configs, (void**)&entry) == SUCCESS)
	{
		entry->cfg->destroy(entry->cfg);
		free(entry);
	}
	configs->destroy(configs);
}

/**
 * Insert entry into match-sorted list, using helper
 */
static void insert_sorted(match_entry_t *entry, linked_list_t *list,
						  linked_list_t *helper)
{
	match_entry_t *current;

	while (list->remove_first(list, (void**)&current) == SUCCESS)
	{
		helper->insert_last(helper, current);
	}
	while (helper->remove_first(helper, (void**)&current) == SUCCESS)
	{
		if (entry && (
			 (entry->match_ike > current->match_ike &&
			  entry->match_peer >= current->match_peer) ||
			 (entry->match_ike >= current->match_ike &&
			  entry->match_peer > current->match_peer)))
		{
			list->insert_last(list, entry);
			entry = NULL;
		}
		list->insert_last(list, current);
	}
	if (entry)
	{
		list->insert_last(list, entry);
	}
}

/**
 * Implements backend_manager_t.create_peer_cfg_enumerator.
 */
static enumerator_t *create_peer_cfg_enumerator(private_backend_manager_t *this,
							host_t *me, host_t *other, identification_t *my_id,
							identification_t *other_id)
{
	enumerator_t *enumerator;
	peer_data_t *data;
	peer_cfg_t *cfg;
	linked_list_t *configs, *helper;

	data = malloc_thing(peer_data_t);
	data->lock = this->lock;
	data->me = my_id;
	data->other = other_id;

	/* create a sorted list with all matches */
	this->lock->read_lock(this->lock);
	enumerator = enumerator_create_nested(
					this->backends->create_enumerator(this->backends),
					(void*)peer_enum_create, data, (void*)peer_enum_destroy);

	if (!me && !other && !my_id && !other_id)
	{	/* shortcut if we are doing a "listall" */
		return enumerator;
	}

	DBG1(DBG_CFG, "looking for peer configs matching %H[%Y]...%H[%Y]",
		 me, my_id, other, other_id);

	configs = linked_list_create();
	/* only once allocated helper list for sorting */
	helper = linked_list_create();
	while (enumerator->enumerate(enumerator, &cfg))
	{
		id_match_t match_peer_me, match_peer_other;
		ike_cfg_match_t match_ike;
		match_entry_t *entry;

		match_peer_me = get_peer_match(my_id, cfg, TRUE);
		match_peer_other = get_peer_match(other_id, cfg, FALSE);
		match_ike = get_ike_match(cfg->get_ike_cfg(cfg), me, other);

		if (match_peer_me && match_peer_other && match_ike)
		{
			DBG2(DBG_CFG, "  candidate \"%s\", match: %d/%d/%d (me/other/ike)",
				 cfg->get_name(cfg), match_peer_me, match_peer_other, match_ike);

			entry = malloc_thing(match_entry_t);
			entry->match_peer = match_peer_me + match_peer_other;
			entry->match_ike = match_ike;
			entry->cfg = cfg->get_ref(cfg);
			insert_sorted(entry, configs, helper);
		}
	}
	enumerator->destroy(enumerator);
	helper->destroy(helper);

	return enumerator_create_filter(configs->create_enumerator(configs),
									(void*)peer_enum_filter, configs,
									(void*)peer_enum_filter_destroy);
}

/**
 * implements backend_manager_t.get_peer_cfg_by_name.
 */
static peer_cfg_t *get_peer_cfg_by_name(private_backend_manager_t *this, char *name)
{
	backend_t *backend;
	peer_cfg_t *config = NULL;
	enumerator_t *enumerator;

	this->lock->read_lock(this->lock);
	enumerator = this->backends->create_enumerator(this->backends);
	while (config == NULL && enumerator->enumerate(enumerator, (void**)&backend))
	{
		config = backend->get_peer_cfg_by_name(backend, name);
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return config;
}

/**
 * Implementation of backend_manager_t.remove_backend.
 */
static void remove_backend(private_backend_manager_t *this, backend_t *backend)
{
	this->lock->write_lock(this->lock);
	this->backends->remove(this->backends, backend, NULL);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of backend_manager_t.add_backend.
 */
static void add_backend(private_backend_manager_t *this, backend_t *backend)
{
	this->lock->write_lock(this->lock);
	this->backends->insert_last(this->backends, backend);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of backend_manager_t.destroy.
 */
static void destroy(private_backend_manager_t *this)
{
	this->backends->destroy(this->backends);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * Described in header-file
 */
backend_manager_t *backend_manager_create()
{
	private_backend_manager_t *this = malloc_thing(private_backend_manager_t);

	this->public.get_ike_cfg = (ike_cfg_t* (*)(backend_manager_t*, host_t*, host_t*))get_ike_cfg;
	this->public.get_peer_cfg_by_name = (peer_cfg_t* (*)(backend_manager_t*,char*))get_peer_cfg_by_name;
	this->public.create_peer_cfg_enumerator = (enumerator_t* (*)(backend_manager_t*,host_t*,host_t*,identification_t*,identification_t*))create_peer_cfg_enumerator;
	this->public.add_backend = (void(*)(backend_manager_t*, backend_t *backend))add_backend;
	this->public.remove_backend = (void(*)(backend_manager_t*, backend_t *backend))remove_backend;
	this->public.destroy = (void (*)(backend_manager_t*))destroy;

	this->backends = linked_list_create();
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	return &this->public;
}

