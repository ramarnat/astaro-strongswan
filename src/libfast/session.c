/*
 * Copyright (C) 2007 Martin Willi
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

#define _GNU_SOURCE

#include "session.h"

#include <string.h>
#include <fcgiapp.h>
#include <stdio.h>

#include <utils/linked_list.h>

#define COOKIE_LEN 16

typedef struct private_session_t private_session_t;

/**
 * private data of the task manager
 */
struct private_session_t {

	/**
	 * public functions
	 */
	session_t public;

	/**
	 * session ID
	 */
	char sid[COOKIE_LEN * 2 + 1];

	/**
	 * have we sent the session cookie?
	 */
	bool cookie_sent;

	/**
	 * list of controller instances controller_t
	 */
	linked_list_t *controllers;

	/**
	 * list of filter instances filter_t
	 */
	linked_list_t *filters;

	/**
	 * user defined session context
	 */
	context_t *context;
};

/**
 * Implementation of session_t.add_controller.
 */
static void add_controller(private_session_t *this, controller_t *controller)
{
	this->controllers->insert_last(this->controllers, controller);
}

/**
 * Implementation of session_t.add_filter.
 */
static void add_filter(private_session_t *this, filter_t *filter)
{
	this->filters->insert_last(this->filters, filter);
}

/**
 * Create a session ID and a cookie
 */
static void create_sid(private_session_t *this)
{
	char buf[COOKIE_LEN];
	rng_t *rng;

	memset(buf, 0, sizeof(buf));
	memset(this->sid, 0, sizeof(this->sid));
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (rng)
	{
		rng->get_bytes(rng, sizeof(buf), buf);
		rng->destroy(rng);
	}
	chunk_to_hex(chunk_create(buf, sizeof(buf)), this->sid, FALSE);
}

/**
 * run all registered filters
 */
static bool run_filter(private_session_t *this, request_t *request, char *p0,
					   char *p1, char *p2, char *p3, char *p4, char *p5)
{
	enumerator_t *enumerator;
	filter_t *filter;

	enumerator = this->filters->create_enumerator(this->filters);
	while (enumerator->enumerate(enumerator, &filter))
	{
		if (!filter->run(filter, request, p0, p1, p2, p3, p4, p5))
		{
			enumerator->destroy(enumerator);
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);
	return TRUE;
}

/**
 * Implementation of session_t.process.
 */
static void process(private_session_t *this, request_t *request)
{
	char *pos, *start, *param[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
	enumerator_t *enumerator;
	bool handled = FALSE;
	controller_t *current;
	int i = 0;

	if (!this->cookie_sent)
	{
		request->add_cookie(request, "SID", this->sid);
		this->cookie_sent = TRUE;
	}

	start = request->get_path(request);
	if (start)
	{
		if (*start == '/')
		{
			start++;
		}
		while ((pos = strchr(start, '/')) != NULL && i < 5)
		{
			param[i++] = strndupa(start, pos - start);
			start = pos + 1;
		}
		param[i] = strdupa(start);

		if (run_filter(this, request, param[0], param[1], param[2], param[3],
						param[4], param[5]))
		{
			enumerator = this->controllers->create_enumerator(this->controllers);
			while (enumerator->enumerate(enumerator, &current))
			{
				if (streq(current->get_name(current), param[0]))
				{
					current->handle(current, request, param[1], param[2],
									param[3], param[4], param[5]);
					handled = TRUE;
					break;
				}
			}
			enumerator->destroy(enumerator);
		}
		else
		{
			handled = TRUE;
		}
	}
	if (!handled)
	{
		if (this->controllers->get_first(this->controllers,
										 (void**)&current) == SUCCESS)
		{
			request->streamf(request,
				"Status: 301 Moved permanently\nLocation: %s/%s\n\n",
				request->get_base(request), current->get_name(current));
		}
	}
}

/**
 * Implementation of session_t.get_sid.
 */
static char* get_sid(private_session_t *this)
{
	return this->sid;
}

/**
 * Implementation of session_t.destroy
 */
static void destroy(private_session_t *this)
{
	this->controllers->destroy_offset(this->controllers, offsetof(controller_t, destroy));
	this->filters->destroy_offset(this->filters, offsetof(filter_t, destroy));
	DESTROY_IF(this->context);
	free(this);
}

/*
 * see header file
 */
session_t *session_create(context_t *context)
{
	private_session_t *this = malloc_thing(private_session_t);

	this->public.add_controller = (void(*)(session_t*, controller_t*))add_controller;
	this->public.add_filter = (void(*)(session_t*, filter_t*))add_filter;
	this->public.process = (void(*)(session_t*,request_t*))process;
	this->public.get_sid = (char*(*)(session_t*))get_sid;
	this->public.destroy = (void(*)(session_t*))destroy;

	create_sid(this);
	this->cookie_sent = FALSE;
	this->controllers = linked_list_create();
	this->filters = linked_list_create();
	this->context = context;

	return &this->public;
}

