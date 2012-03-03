/*
 * Copyright (C) 2006-2009 Martin Willi
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

#include "acquire_job.h"

#include <daemon.h>


typedef struct private_acquire_job_t private_acquire_job_t;

/**
 * Private data of an acquire_job_t object.
 */
struct private_acquire_job_t {
	/**
	 * Public acquire_job_t interface.
	 */
	acquire_job_t public;

	/**
	 * reqid of the child to rekey
	 */
	u_int32_t reqid;

	/**
	 * acquired source traffic selector
	 */
	traffic_selector_t *src_ts;

	/**
	 * acquired destination traffic selector
	 */
	traffic_selector_t *dst_ts;
};

/**
 * Implementation of job_t.destroy.
 */
static void destroy(private_acquire_job_t *this)
{
	DESTROY_IF(this->src_ts);
	DESTROY_IF(this->dst_ts);
	free(this);
}

/**
 * Implementation of job_t.execute.
 */
static void execute(private_acquire_job_t *this)
{
	charon->traps->acquire(charon->traps, this->reqid,
						   this->src_ts, this->dst_ts);
	destroy(this);
}

/*
 * Described in header
 */
acquire_job_t *acquire_job_create(u_int32_t reqid,
								  traffic_selector_t *src_ts,
								  traffic_selector_t *dst_ts)
{
	private_acquire_job_t *this = malloc_thing(private_acquire_job_t);

	this->public.job_interface.execute = (void (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*)(job_t*)) destroy;

	this->reqid = reqid;
	this->src_ts = src_ts;
	this->dst_ts = dst_ts;

	return &this->public;
}

