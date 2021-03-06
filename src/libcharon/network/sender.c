/*
 * Copyright (C) 2005-2006 Martin Willi
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

#include <unistd.h>
#include <stdlib.h>

#include "sender.h"

#include <daemon.h>
#include <network/socket.h>
#include <processing/jobs/callback_job.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <threading/mutex.h>


typedef struct private_sender_t private_sender_t;

/**
 * Private data of a sender_t object.
 */
struct private_sender_t {
	/**
	 * Public part of a sender_t object.
	 */
	sender_t public;

	/**
	 * Sender threads job.
	 */
	callback_job_t *job;

	/**
	 * The packets are stored in a linked list
	 */
	linked_list_t *list;

	/**
	 * mutex to synchronize access to list
	 */
	mutex_t *mutex;

	/**
	 * condvar to signal for packets added to list
	 */
	condvar_t *got;

	/**
	 * condvar to signal for packets sent
	 */
	condvar_t *sent;

	/**
	 * Delay for sending outgoing packets, to simulate larger RTT
	 */
	int send_delay;

	/**
	 * Specific message type to delay, 0 for any
	 */
	int send_delay_type;

	/**
	 * Delay request messages?
	 */
	bool send_delay_request;

	/**
	 * Delay response messages?
	 */
	bool send_delay_response;
};

METHOD(sender_t, send_, void,
	private_sender_t *this, packet_t *packet)
{
	host_t *src, *dst;

	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	DBG1(DBG_NET, "sending packet: from %#H to %#H", src, dst);

	if (this->send_delay)
	{
		message_t *message;

		message = message_create_from_packet(packet->clone(packet));
		if (message->parse_header(message) == SUCCESS)
		{
			if (this->send_delay_type == 0 ||
				this->send_delay_type == message->get_exchange_type(message))
			{
				if ((message->get_request(message) && this->send_delay_request) ||
					(!message->get_request(message) && this->send_delay_response))
				{
					DBG1(DBG_NET, "using send delay: %dms", this->send_delay);
					usleep(this->send_delay * 1000);
				}
			}
		}
		message->destroy(message);
	}

	this->mutex->lock(this->mutex);
	this->list->insert_last(this->list, packet);
	this->got->signal(this->got);
	this->mutex->unlock(this->mutex);
}

/**
 * Job callback function to send packets
 */
static job_requeue_t send_packets(private_sender_t * this)
{
	packet_t *packet;
	bool oldstate;

	this->mutex->lock(this->mutex);
	while (this->list->get_count(this->list) == 0)
	{
		/* add cleanup handler, wait for packet, remove cleanup handler */
		thread_cleanup_push((thread_cleanup_t)this->mutex->unlock, this->mutex);
		oldstate = thread_cancelability(TRUE);

		this->got->wait(this->got, this->mutex);

		thread_cancelability(oldstate);
		thread_cleanup_pop(FALSE);
	}
	this->list->remove_first(this->list, (void**)&packet);
	this->sent->signal(this->sent);
	this->mutex->unlock(this->mutex);

	charon->socket->send(charon->socket, packet);
	packet->destroy(packet);
	return JOB_REQUEUE_DIRECT;
}

METHOD(sender_t, destroy, void,
	private_sender_t *this)
{
	/* send all packets in the queue */
	this->mutex->lock(this->mutex);
	while (this->list->get_count(this->list))
	{
		this->sent->wait(this->sent, this->mutex);
	}
	this->mutex->unlock(this->mutex);
	this->job->cancel(this->job);
	this->list->destroy(this->list);
	this->got->destroy(this->got);
	this->sent->destroy(this->sent);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
sender_t * sender_create()
{
	private_sender_t *this;

	INIT(this,
		.public = {
			.send = _send_,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.got = condvar_create(CONDVAR_TYPE_DEFAULT),
		.sent = condvar_create(CONDVAR_TYPE_DEFAULT),
		.job = callback_job_create((callback_job_cb_t)send_packets,
									this, NULL, NULL),
		.send_delay = lib->settings->get_int(lib->settings,
											"charon.send_delay", 0),
		.send_delay_type = lib->settings->get_int(lib->settings,
											"charon.send_delay_type", 0),
		.send_delay_request = lib->settings->get_bool(lib->settings,
											"charon.send_delay_request", TRUE),
		.send_delay_response = lib->settings->get_int(lib->settings,
											"charon.send_delay_response", TRUE),
	);

	charon->processor->queue_job(charon->processor, (job_t*)this->job);

	return &this->public;
}

