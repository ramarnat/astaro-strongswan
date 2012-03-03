/*
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "process_message_job.h"

#include <daemon.h>

typedef struct private_process_message_job_t private_process_message_job_t;

/**
 * Private data of an process_message_job_t Object
 */
struct private_process_message_job_t {
	/**
	 * public process_message_job_t interface
	 */
	process_message_job_t public;

	/**
	 * Message associated with this job
	 */
	message_t *message;
};

/**
 * Implements job_t.destroy.
 */
static void destroy(private_process_message_job_t *this)
{
	this->message->destroy(this->message);
	free(this);
}

/**
 * Implementation of job_t.execute.
 */
static void execute(private_process_message_job_t *this)
{
	ike_sa_t *ike_sa;

#ifdef ME
	/* if this is an unencrypted INFORMATIONAL exchange it is likely a
	 * connectivity check. */
	if (this->message->get_exchange_type(this->message) == INFORMATIONAL &&
		this->message->get_first_payload_type(this->message) != ENCRYPTED)
	{
		/* theoretically this could also be an error message
		 * see RFC 4306, section 1.5. */
		DBG1(DBG_NET, "received unencrypted informational: from %#H to %#H",
			 this->message->get_source(this->message),
			 this->message->get_destination(this->message));
		charon->connect_manager->process_check(charon->connect_manager, this->message);
		destroy(this);
		return;
	}
#endif /* ME */

	ike_sa = charon->ike_sa_manager->checkout_by_message(charon->ike_sa_manager,
														 this->message);
	if (ike_sa)
	{
		DBG1(DBG_NET, "received packet: from %#H to %#H",
			 this->message->get_source(this->message),
			 this->message->get_destination(this->message));
		if (ike_sa->process_message(ike_sa, this->message) == DESTROY_ME)
		{
			charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
														ike_sa);
		}
		else
		{
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		}
	}
	destroy(this);
}

/*
 * Described in header
 */
process_message_job_t *process_message_job_create(message_t *message)
{
	private_process_message_job_t *this = malloc_thing(private_process_message_job_t);

	/* interface functions */
	this->public.job_interface.execute = (void (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void(*)(job_t*))destroy;

	/* private variables */
	this->message = message;

	return &(this->public);
}
