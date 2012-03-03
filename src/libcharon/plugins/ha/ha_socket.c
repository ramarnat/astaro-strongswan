/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "ha_socket.h"
#include "ha_plugin.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <daemon.h>
#include <utils/host.h>
#include <processing/jobs/callback_job.h>

typedef struct private_ha_socket_t private_ha_socket_t;

/**
 * Private data of an ha_socket_t object.
 */
struct private_ha_socket_t {

	/**
	 * Public ha_socket_t interface.
	 */
	ha_socket_t public;

	/**
	 * UDP communication socket fd
	 */
	int fd;

	/**
	 * local host to receive/send from
	 */
	host_t *local;

	/**
	 * remote host to receive/send to
	 */
	host_t *remote;
};

/**
 * Data to pass to the send_message() callback job
 */
typedef struct {
	ha_message_t *message;
	private_ha_socket_t *this;
} job_data_t;

/**
 * Cleanup job data
 */
static void job_data_destroy(job_data_t *this)
{
	this->message->destroy(this->message);
	free(this);
}

/**
 * Callback to asynchronously send messages
 */
static job_requeue_t send_message(job_data_t *data)
{
	private_ha_socket_t *this;
	chunk_t chunk;

	this = data->this;
	chunk = data->message->get_encoding(data->message);
	if (send(this->fd, chunk.ptr, chunk.len, 0) < chunk.len)
	{
		DBG1(DBG_CFG, "pushing HA message failed: %s", strerror(errno));
	}
	return JOB_REQUEUE_NONE;
}

/**
 * Implementation of ha_socket_t.push
 */
static void push(private_ha_socket_t *this, ha_message_t *message)
{
	chunk_t chunk;

	/* Try to send synchronously, but non-blocking. */
	chunk = message->get_encoding(message);
	if (send(this->fd, chunk.ptr, chunk.len, MSG_DONTWAIT) < chunk.len)
	{
		if (errno == EAGAIN)
		{
			callback_job_t *job;
			job_data_t *data;

			/* Fallback to asynchronous transmission. This is required, as sendto()
			 * is a blocking call if it acquires a policy. We could end up in a
			 * deadlock, as we own an IKE_SA. */
			data = malloc_thing(job_data_t);
			data->message = message;
			data->this = this;

			job = callback_job_create((callback_job_cb_t)send_message,
									  data, (void*)job_data_destroy, NULL);
			charon->processor->queue_job(charon->processor, (job_t*)job);
			return;
		}
		DBG1(DBG_CFG, "pushing HA message failed: %s", strerror(errno));
	}
	message->destroy(message);
}

/**
 * Implementation of ha_socket_t.pull
 */
static ha_message_t *pull(private_ha_socket_t *this)
{
	while (TRUE)
	{
		ha_message_t *message;
		char buf[1024];
		int oldstate;
		ssize_t len;

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		len = recv(this->fd, buf, sizeof(buf), 0);
		pthread_setcancelstate(oldstate, NULL);
		if (len <= 0)
		{
			switch (errno)
			{
				case ECONNREFUSED:
				case EINTR:
					continue;
				default:
					DBG1(DBG_CFG, "pulling HA message failed: %s",
						 strerror(errno));
					sleep(1);
			}
		}
		message = ha_message_parse(chunk_create(buf, len));
		if (message)
		{
			return message;
		}
	}
}

/**
 * Open and connect the HA socket
 */
static bool open_socket(private_ha_socket_t *this)
{
	this->fd = socket(this->local->get_family(this->local), SOCK_DGRAM, 0);
	if (this->fd == -1)
	{
		DBG1(DBG_CFG, "opening HA socket failed: %s", strerror(errno));
		return FALSE;
	}

	if (bind(this->fd, this->local->get_sockaddr(this->local),
			 *this->local->get_sockaddr_len(this->local)) == -1)
	{
		DBG1(DBG_CFG, "binding HA socket failed: %s", strerror(errno));
		close(this->fd);
		this->fd = -1;
		return FALSE;
	}
	if (connect(this->fd, this->remote->get_sockaddr(this->remote),
				*this->remote->get_sockaddr_len(this->remote)) == -1)
	{
		DBG1(DBG_CFG, "connecting HA socket failed: %s", strerror(errno));
		close(this->fd);
		this->fd = -1;
		return FALSE;
	}

	return TRUE;
}

/**
 * Implementation of ha_socket_t.destroy.
 */
static void destroy(private_ha_socket_t *this)
{
	if (this->fd != -1)
	{
		close(this->fd);
	}
	DESTROY_IF(this->local);
	DESTROY_IF(this->remote);
	free(this);
}

/**
 * See header
 */
ha_socket_t *ha_socket_create(char *local, char *remote)
{
	private_ha_socket_t *this = malloc_thing(private_ha_socket_t);

	this->public.push = (void(*)(ha_socket_t*, ha_message_t*))push;
	this->public.pull = (ha_message_t*(*)(ha_socket_t*))pull;
	this->public.destroy = (void(*)(ha_socket_t*))destroy;

	this->local = host_create_from_dns(local, 0, HA_PORT);
	this->remote = host_create_from_dns(remote, 0, HA_PORT);
	this->fd = -1;

	if (!this->local || !this->remote)
	{
		DBG1(DBG_CFG, "invalid local/remote HA address");
		destroy(this);
		return NULL;
	}
	if (!open_socket(this))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

