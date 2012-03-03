/*
 * Copyright (C) 2007 Tobias Brunner
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

#include "mediation_job.h"

#include <encoding/payloads/endpoint_notify.h>
#include <daemon.h>


typedef struct private_mediation_job_t private_mediation_job_t;

/**
 * Private data of an mediation_job_t Object
 */
struct private_mediation_job_t {
	/**
	 * public mediation_job_t interface
	 */
	mediation_job_t public;

	/**
	 * ID of target peer.
	 */
	identification_t *target;

	/**
	 * ID of the source peer.
	 */
	identification_t *source;

	/**
	 * ME_CONNECTID
	 */
	chunk_t connect_id;

	/**
	 * ME_CONNECTKEY
	 */
	chunk_t connect_key;

	/**
	 * Submitted endpoints
	 */
	linked_list_t *endpoints;

	/**
	 * Is this a callback job?
	 */
	bool callback;

	/**
	 * Is this a response?
	 */
	bool response;
};

/**
 * Implements job_t.destroy.
 */
static void destroy(private_mediation_job_t *this)
{
	DESTROY_IF(this->target);
	DESTROY_IF(this->source);
	chunk_free(&this->connect_id);
	chunk_free(&this->connect_key);
	DESTROY_OFFSET_IF(this->endpoints, offsetof(endpoint_notify_t, destroy));
	free(this);
}

/**
 * Implementation of job_t.execute.
 */
static void execute(private_mediation_job_t *this)
{
	ike_sa_id_t *target_sa_id;

	target_sa_id = charon->mediation_manager->check(charon->mediation_manager, this->target);

	if (target_sa_id)
	{
		ike_sa_t *target_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
											  target_sa_id);
		if (target_sa)
		{
			if (this->callback)
			{
				/* send callback to a peer */
				if (target_sa->callback(target_sa, this->source) != SUCCESS)
				{
					DBG1(DBG_JOB, "callback for '%Y' to '%Y' failed",
							this->source, this->target);
					charon->ike_sa_manager->checkin(charon->ike_sa_manager, target_sa);
					destroy(this);
					return;
				}
			}
			else
			{
				/* normal mediation between two peers */
				if (target_sa->relay(target_sa, this->source, this->connect_id,
						this->connect_key, this->endpoints, this->response) != SUCCESS)
				{
					DBG1(DBG_JOB, "mediation between '%Y' and '%Y' failed",
							this->source, this->target);
					charon->ike_sa_manager->checkin(charon->ike_sa_manager, target_sa);
					/* FIXME: notify the initiator */
					destroy(this);
					return;
				}
			}

			charon->ike_sa_manager->checkin(charon->ike_sa_manager, target_sa);
		}
		else
		{
			DBG1(DBG_JOB, "mediation between '%Y' and '%Y' failed: "
					"SA not found", this->source, this->target);
		}
	}
	else
	{
		DBG1(DBG_JOB, "mediation between '%Y' and '%Y' failed: "
				"peer is not online anymore", this->source, this->target);
	}
	destroy(this);
}

/**
 * Creates an empty mediation job
 */
static private_mediation_job_t *mediation_job_create_empty()
{
	private_mediation_job_t *this = malloc_thing(private_mediation_job_t);

	/* interface functions */
	this->public.job_interface.execute = (void (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;

	/* private variables */
	this->target = NULL;
	this->source = NULL;
	this->callback = FALSE;
	this->connect_id = chunk_empty;
	this->connect_key = chunk_empty;
	this->endpoints = NULL;
	this->response = FALSE;

	return this;
}

/*
 * Described in header
 */
mediation_job_t *mediation_job_create(identification_t *peer_id,
		identification_t *requester, chunk_t connect_id, chunk_t connect_key,
		linked_list_t *endpoints, bool response)
{
	private_mediation_job_t *this = mediation_job_create_empty();

	this->target = peer_id->clone(peer_id);
	this->source = requester->clone(requester);
	this->connect_id = chunk_clone(connect_id);
	this->connect_key = chunk_clone(connect_key);
	this->endpoints = endpoints->clone_offset(endpoints, offsetof(endpoint_notify_t, clone));
	this->response = response;

	return &this->public;
}

/*
 * Described in header
 */
mediation_job_t *mediation_callback_job_create(identification_t *requester,
		identification_t *peer_id)
{
	private_mediation_job_t *this = mediation_job_create_empty();

	this->target = requester->clone(requester);
	this->source = peer_id->clone(peer_id);
	this->callback = TRUE;

	return &this->public;
}
