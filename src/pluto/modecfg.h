/* Mode Config related functions
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003-2004 Xelerance Corporation
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

#ifndef _MODECFG_H
#define _MODECFG_H

#include <chunk.h>
#include <attributes/attribute_handler.h>

#include "state.h"
#include "demux.h"

typedef struct modecfg_attribute_t modecfg_attribute_t;

/**
 * Defines a modecfg_attribute_t object.
 */
struct modecfg_attribute_t {
	/**
	 * Type of the attribute.
	 */
	u_int16_t type;

	/**
	 * Attribute is coded as TV
	 */
	bool is_tv;

	/**
	 * Attribute value as chunk.
	 */
	chunk_t value;

	/**
	 * Attribute handler.
	 */
	attribute_handler_t *handler;
};

/* Destroys a modecfg_attribute_t object */
extern void modecfg_attribute_destroy(modecfg_attribute_t *this);

/* ModeConfig pull mode start function */
extern stf_status modecfg_send_request(struct state *st);

/* ModeConfig pull mode state transition functions */
extern stf_status modecfg_inR0(struct msg_digest *md);
extern stf_status modecfg_inI1(struct msg_digest *md);

/* ModeConfig push mode start function */
extern stf_status modecfg_send_set(struct state *st);

/* ModeConfig push mode state transition functions */
extern stf_status modecfg_inI0(struct msg_digest *md);
extern stf_status modecfg_inR3(struct msg_digest *md);

/* XAUTH start function */
extern stf_status xauth_send_request(struct state *st);

/* XAUTH state transition funcgtions */
extern stf_status xauth_inI0(struct msg_digest *md);
extern stf_status xauth_inR1(struct msg_digest *md);
extern stf_status xauth_inI1(struct msg_digest *md);
extern stf_status xauth_inR2(struct msg_digest *md);

#endif /* _MODECFG_H */
