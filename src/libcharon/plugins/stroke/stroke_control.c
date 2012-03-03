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

#include "stroke_control.h"

#include <daemon.h>
#include <processing/jobs/delete_ike_sa_job.h>

typedef struct private_stroke_control_t private_stroke_control_t;

/**
 * private data of stroke_control
 */
struct private_stroke_control_t {

	/**
	 * public functions
	 */
	stroke_control_t public;
};


typedef struct stroke_log_info_t stroke_log_info_t;

/**
 * helper struct to say what and where to log when using controller callback
 */
struct stroke_log_info_t {

	/**
	 * level to log up to
	 */
	level_t level;

	/**
	 * where to write log
	 */
	FILE* out;
};

/**
 * logging to the stroke interface
 */
static bool stroke_log(stroke_log_info_t *info, debug_t group, level_t level,
					   ike_sa_t *ike_sa, char *format, va_list args)
{
	if (level <= info->level)
	{
		if (vfprintf(info->out, format, args) < 0 ||
			fprintf(info->out, "\n") < 0 ||
			fflush(info->out) != 0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * get the child_cfg with the same name as the peer cfg
 */
static child_cfg_t* get_child_from_peer(peer_cfg_t *peer_cfg, char *name)
{
	child_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;

	enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(current->get_name(current), name))
		{
			found = current;
			found->get_ref(found);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Implementation of stroke_control_t.initiate.
 */
static void initiate(private_stroke_control_t *this, stroke_msg_t *msg, FILE *out)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	stroke_log_info_t info;

	peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
													  msg->initiate.name);
	if (peer_cfg == NULL)
	{
		DBG1(DBG_CFG, "no config named '%s'\n", msg->initiate.name);
		return;
	}
	if (peer_cfg->get_ike_version(peer_cfg) != 2)
	{
		DBG1(DBG_CFG, "ignoring initiation request for IKEv%d config",
			 peer_cfg->get_ike_version(peer_cfg));
		peer_cfg->destroy(peer_cfg);
		return;
	}

	child_cfg = get_child_from_peer(peer_cfg, msg->initiate.name);
	if (child_cfg == NULL)
	{
		DBG1(DBG_CFG, "no child config named '%s'\n", msg->initiate.name);
		peer_cfg->destroy(peer_cfg);
		return;
	}

	if (msg->output_verbosity < 0)
	{
		charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
									 NULL, NULL);
	}
	else
	{
		info.out = out;
		info.level = msg->output_verbosity;
		charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
									 (controller_cb_t)stroke_log, &info);
	}
}

/**
 * Implementation of stroke_control_t.terminate.
 */
static void terminate(private_stroke_control_t *this, stroke_msg_t *msg, FILE *out)
{
	char *string, *pos = NULL, *name = NULL;
	u_int32_t id = 0;
	bool child, all = FALSE;
	int len;
	ike_sa_t *ike_sa;
	enumerator_t *enumerator;
	linked_list_t *ike_list, *child_list;
	stroke_log_info_t info;
	uintptr_t del;

	string = msg->terminate.name;

	len = strlen(string);
	if (len < 1)
	{
		DBG1(DBG_CFG, "error parsing string");
		return;
	}
	switch (string[len-1])
	{
		case '}':
			child = TRUE;
			pos = strchr(string, '{');
			break;
		case ']':
			child = FALSE;
			pos = strchr(string, '[');
			break;
		default:
			name = string;
			child = FALSE;
			break;
	}

	if (name)
	{
		/* is a single name */
	}
	else if (pos == string + len - 2)
	{	/* is name[] or name{} */
		string[len-2] = '\0';
		name = string;
	}
	else
	{
		if (*(pos + 1) == '*')
		{	/* is name[*] */
			all = TRUE;
			*pos = '\0';
			name = string;
		}
		else
		{	/* is name[123] or name{23} */
			id = atoi(pos + 1);
			if (id == 0)
			{
				DBG1(DBG_CFG, "error parsing string");
				return;
			}
		}
	}

	info.out = out;
	info.level = msg->output_verbosity;

	if (id)
	{
		if (child)
		{
			charon->controller->terminate_child(charon->controller, id,
									(controller_cb_t)stroke_log, &info);
		}
		else
		{
			charon->controller->terminate_ike(charon->controller, id,
									(controller_cb_t)stroke_log, &info);
		}
		return;
	}

	ike_list = linked_list_create();
	child_list = linked_list_create();
	enumerator = charon->controller->create_ike_sa_enumerator(charon->controller);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		child_sa_t *child_sa;
		iterator_t *children;

		if (child)
		{
			children = ike_sa->create_child_sa_iterator(ike_sa);
			while (children->iterate(children, (void**)&child_sa))
			{
				if (streq(name, child_sa->get_name(child_sa)))
				{
					child_list->insert_last(child_list,
							(void*)(uintptr_t)child_sa->get_reqid(child_sa));
					if (!all)
					{
						break;
					}
				}
			}
			children->destroy(children);
			if (child_list->get_count(child_list) && !all)
			{
				break;
			}
		}
		else if (streq(name, ike_sa->get_name(ike_sa)))
		{
			ike_list->insert_last(ike_list,
						(void*)(uintptr_t)ike_sa->get_unique_id(ike_sa));
			if (!all)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	enumerator = child_list->create_enumerator(child_list);
	while (enumerator->enumerate(enumerator, &del))
	{
		charon->controller->terminate_child(charon->controller, del,
									(controller_cb_t)stroke_log, &info);
	}
	enumerator->destroy(enumerator);

	enumerator = ike_list->create_enumerator(ike_list);
	while (enumerator->enumerate(enumerator, &del))
	{
		charon->controller->terminate_ike(charon->controller, del,
									(controller_cb_t)stroke_log, &info);
	}
	enumerator->destroy(enumerator);

	if (child_list->get_count(child_list) == 0 &&
		ike_list->get_count(ike_list) == 0)
	{
		DBG1(DBG_CFG, "no %s_SA named '%s' found",
			 child ? "CHILD" : "IKE", name);
	}
	ike_list->destroy(ike_list);
	child_list->destroy(child_list);
}

/**
 * Implementation of stroke_control_t.terminate_srcip.
 */
static void terminate_srcip(private_stroke_control_t *this,
							stroke_msg_t *msg, FILE *out)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	host_t *start = NULL, *end = NULL, *vip;
	chunk_t chunk_start, chunk_end = chunk_empty, chunk_vip;

	if (msg->terminate_srcip.start)
	{
		start = host_create_from_string(msg->terminate_srcip.start, 0);
	}
	if (!start)
	{
		DBG1(DBG_CFG, "invalid start address: %s", msg->terminate_srcip.start);
		return;
	}
	chunk_start = start->get_address(start);
	if (msg->terminate_srcip.end)
	{
		end = host_create_from_string(msg->terminate_srcip.end, 0);
		if (!end)
		{
			DBG1(DBG_CFG, "invalid end address: %s", msg->terminate_srcip.end);
			start->destroy(start);
			return;
		}
		chunk_end = end->get_address(end);
	}

	enumerator = charon->controller->create_ike_sa_enumerator(charon->controller);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		vip = ike_sa->get_virtual_ip(ike_sa, FALSE);
		if (!vip)
		{
			continue;
		}
		if (!end)
		{
			if (!vip->ip_equals(vip, start))
			{
				continue;
			}
		}
		else
		{
			chunk_vip = vip->get_address(vip);
			if (chunk_vip.len != chunk_start.len ||
				chunk_vip.len != chunk_end.len ||
				memcmp(chunk_vip.ptr, chunk_start.ptr, chunk_vip.len) < 0 ||
				memcmp(chunk_vip.ptr, chunk_end.ptr, chunk_vip.len) > 0)
			{
				continue;
			}
		}

		/* schedule delete asynchronously */
		charon->processor->queue_job(charon->processor, (job_t*)
						delete_ike_sa_job_create(ike_sa->get_id(ike_sa), TRUE));
	}
	enumerator->destroy(enumerator);
	start->destroy(start);
	DESTROY_IF(end);
}

/**
 * Implementation of stroke_control_t.purge_ike
 */
static void purge_ike(private_stroke_control_t *this, stroke_msg_t *msg, FILE *out)
{
	enumerator_t *enumerator;
	iterator_t *iterator;
	ike_sa_t *ike_sa;
	child_sa_t *child_sa;
	linked_list_t *list;
	uintptr_t del;
	stroke_log_info_t info;

	info.out = out;
	info.level = msg->output_verbosity;

	list = linked_list_create();
	enumerator = charon->controller->create_ike_sa_enumerator(charon->controller);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		iterator = ike_sa->create_child_sa_iterator(ike_sa);
		if (!iterator->iterate(iterator, (void**)&child_sa))
		{
			list->insert_last(list,
						(void*)(uintptr_t)ike_sa->get_unique_id(ike_sa));
		}
		iterator->destroy(iterator);
	}
	enumerator->destroy(enumerator);

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &del))
	{
		charon->controller->terminate_ike(charon->controller, del,
									(controller_cb_t)stroke_log, &info);
	}
	enumerator->destroy(enumerator);
	list->destroy(list);
}

/**
 * Implementation of stroke_control_t.route.
 */
static void route(private_stroke_control_t *this, stroke_msg_t *msg, FILE *out)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;

	peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
													  msg->route.name);
	if (peer_cfg == NULL)
	{
		fprintf(out, "no config named '%s'\n", msg->route.name);
		return;
	}
	if (peer_cfg->get_ike_version(peer_cfg) != 2)
	{
		peer_cfg->destroy(peer_cfg);
		return;
	}

	child_cfg = get_child_from_peer(peer_cfg, msg->route.name);
	if (child_cfg == NULL)
	{
		fprintf(out, "no child config named '%s'\n", msg->route.name);
		peer_cfg->destroy(peer_cfg);
		return;
	}

	if (charon->traps->install(charon->traps, peer_cfg, child_cfg))
	{
		fprintf(out, "configuration '%s' routed\n", msg->route.name);
	}
	else
	{
		fprintf(out, "routing configuration '%s' failed\n", msg->route.name);
	}
	peer_cfg->destroy(peer_cfg);
	child_cfg->destroy(child_cfg);
}

/**
 * Implementation of stroke_control_t.unroute.
 */
static void unroute(private_stroke_control_t *this, stroke_msg_t *msg, FILE *out)
{
	child_sa_t *child_sa;
	enumerator_t *enumerator;
	u_int32_t id;

	enumerator = charon->traps->create_enumerator(charon->traps);
	while (enumerator->enumerate(enumerator, NULL, &child_sa))
	{
		if (streq(msg->unroute.name, child_sa->get_name(child_sa)))
		{
			id = child_sa->get_reqid(child_sa);
			enumerator->destroy(enumerator);
			charon->traps->uninstall(charon->traps, id);
			fprintf(out, "configuration '%s' unrouted\n", msg->unroute.name);
			return;
		}
	}
	enumerator->destroy(enumerator);
	fprintf(out, "configuration '%s' not found\n", msg->unroute.name);
}

/**
 * Implementation of stroke_control_t.destroy
 */
static void destroy(private_stroke_control_t *this)
{
	free(this);
}

/*
 * see header file
 */
stroke_control_t *stroke_control_create()
{
	private_stroke_control_t *this = malloc_thing(private_stroke_control_t);

	this->public.initiate = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))initiate;
	this->public.terminate = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))terminate;
	this->public.terminate_srcip = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))terminate_srcip;
	this->public.purge_ike = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))purge_ike;
	this->public.route = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))route;
	this->public.unroute = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))unroute;
	this->public.destroy = (void(*)(stroke_control_t*))destroy;

	return &this->public;
}

