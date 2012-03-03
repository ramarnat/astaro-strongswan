/*
 * Copyright (C) 2007 Tobias Brunner
 * Copyright (C) 2006 Martin Willi
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

/**
 * @defgroup task task
 * @{ @ingroup tasks
 */

#ifndef TASK_H_
#define TASK_H_

typedef enum task_type_t task_type_t;
typedef struct task_t task_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <encoding/message.h>

/**
 * Different kinds of tasks.
 */
enum task_type_t {
	/** establish an unauthenticated IKE_SA */
	IKE_INIT,
	/** detect NAT situation */
	IKE_NATD,
	/** handle MOBIKE stuff */
	IKE_MOBIKE,
	/** authenticate the initiated IKE_SA */
	IKE_AUTHENTICATE,
	/** AUTH_LIFETIME negotiation, RFC4478 */
	IKE_AUTH_LIFETIME,
	/** certificate processing before authentication (certreqs, cert parsing) */
	IKE_CERT_PRE,
	/** certificate processing after authentication (certs payload generation) */
	IKE_CERT_POST,
	/** Configuration payloads, virtual IP and such */
	IKE_CONFIG,
	/** rekey an IKE_SA */
	IKE_REKEY,
	/** reestablish a complete IKE_SA */
	IKE_REAUTH,
	/** delete an IKE_SA */
	IKE_DELETE,
	/** liveness check */
	IKE_DPD,
	/** Vendor ID processing */
	IKE_VENDOR,
#ifdef ME
	/** handle ME stuff */
	IKE_ME,
#endif /* ME */
	/** establish a CHILD_SA within an IKE_SA */
	CHILD_CREATE,
	/** delete an established CHILD_SA */
	CHILD_DELETE,
	/** rekey an CHILD_SA */
	CHILD_REKEY,
};

/**
 * enum names for task_type_t.
 */
extern enum_name_t *task_type_names;

/**
 * Interface for a task, an operation handled within exchanges.
 *
 * A task is an elemantary operation. It may be handled by a single or by
 * multiple exchanges. An exchange may even complete multiple tasks.
 * A task has a build() and an process() operation. The build() operation
 * creates payloads and adds it to the message. The process() operation
 * inspects a message and handles its payloads. An initiator of an exchange
 * first calls build() to build the request, and processes the response message
 * with the process() method.
 * A responder does the opposite; it calls process() first to handle an incoming
 * request and secondly calls build() to build an appropriate response.
 * Both methods return either SUCCESS, NEED_MORE or FAILED. A SUCCESS indicates
 * that the task completed, even when the task completed unsuccesfully. The
 * manager then removes the task from the list. A NEED_MORE is returned when
 * the task needs further build()/process() calls to complete, the manager
 * leaves the taks in the queue. A returned FAILED indicates a critical failure.
 * The manager closes the IKE_SA whenever a task returns FAILED.
 */
struct task_t {

	/**
	 * Build a request or response message for this task.
	 *
	 * @param message		message to add payloads to
	 * @return
	 *						- FAILED if a critical error occured
	 *						- DESTROY_ME if IKE_SA has been properly deleted
	 *						- NEED_MORE if another call to build/process needed
	 *						- SUCCESS if task completed
	 */
	status_t (*build) (task_t *this, message_t *message);

	/**
	 * Process a request or response message for this task.
	 *
	 * @param message		message to read payloads from
	 * @return
	 * 						- FAILED if a critical error occured
	 *						- DESTROY_ME if IKE_SA has been properly deleted
	 *						- NEED_MORE if another call to build/process needed
	 *						- SUCCESS if task completed
	 */
	status_t (*process) (task_t *this, message_t *message);

	/**
	 * Get the type of the task implementation.
	 */
	task_type_t (*get_type) (task_t *this);

	/**
	 * Migrate a task to a new IKE_SA.
	 *
	 * After migrating a task, it goes back to a state where it can be
	 * used again to initate an exchange. This is useful when a task
	 * has to get migrated to a new IKE_SA.
	 * A special usage is when a INVALID_KE_PAYLOAD is received. A call
	 * to reset resets the task, but uses another DH group for the next
	 * try.
	 * The ike_sa is the new IKE_SA this task belongs to and operates on.
	 *
	 * @param ike_sa		new IKE_SA this task works for
	 */
	void (*migrate) (task_t *this, ike_sa_t *ike_sa);

	/**
	 * Destroys a task_t object.
	 */
	void (*destroy) (task_t *this);
};

#endif /** TASK_H_ @}*/
