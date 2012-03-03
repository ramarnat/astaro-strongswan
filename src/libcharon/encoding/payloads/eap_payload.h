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

/**
 * @defgroup eap_payload eap_payload
 * @{ @ingroup payloads
 */

#ifndef EAP_PAYLOAD_H_
#define EAP_PAYLOAD_H_

typedef struct eap_payload_t eap_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <sa/authenticators/eap/eap_method.h>

/**
 * Length of a EAP payload without the EAP Message in bytes.
 */
#define EAP_PAYLOAD_HEADER_LENGTH 4

/**
 * Class representing an IKEv2 EAP payload.
 *
 * The EAP payload format is described in RFC section 3.16.
 */
struct eap_payload_t {

	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Set the contained EAP data.
	 *
	 * This contains the FULL EAP message starting with "code".
	 * Chunk gets cloned.
	 *
	 * @param message	EAP data
	 */
	void (*set_data) (eap_payload_t *this, chunk_t data);

	/**
	 * Get the contained EAP data.
	 *
	 * This contains the FULL EAP message starting with "code".
	 *
	 * @return			EAP data (pointer to internal data)
	 */
	chunk_t (*get_data) (eap_payload_t *this);

	/**
	 * Get the EAP code.
	 *
	 * @return			EAP message as chunk_t
	 */
	eap_code_t (*get_code) (eap_payload_t *this);

	/**
	 * Get the EAP identifier.
	 *
	 * @return			unique identifier
	 */
	u_int8_t (*get_identifier) (eap_payload_t *this);

	/**
	 * Get the EAP method type.
	 *
	 * @param vendor	pointer receiving vendor identifier
	 * @return			EAP method type, vendor specific if vendor != 0
	 */
	eap_type_t (*get_type) (eap_payload_t *this, u_int32_t *vendor);

	/**
	 * Destroys an eap_payload_t object.
	 */
	void (*destroy) (eap_payload_t *this);
};

/**
 * Creates an empty eap_payload_t object.
 *
 * @return eap_payload_t object
 */
eap_payload_t *eap_payload_create(void);

/**
 * Creates an eap_payload_t object with data.
 *
 * @return eap_payload_t object
 */
eap_payload_t *eap_payload_create_data(chunk_t data);

/**
 * Creates an eap_payload_t object with a code.
 *
 * Could should be either EAP_SUCCESS/EAP_FAILURE, use
 * constructor above otherwise.
 *
 * @param code			EAP status code
 * @param identifier	EAP identifier to use in payload
 * @return 				eap_payload_t object
 */
eap_payload_t *eap_payload_create_code(eap_code_t code, u_int8_t identifier);

/**
 * Creates an eap_payload_t EAP_RESPONSE containing an EAP_NAK.
 *
 * @param identifier	EAP identifier to use in payload
 * @return 				eap_payload_t object
 */
eap_payload_t *eap_payload_create_nak(u_int8_t identifier);

#endif /** EAP_PAYLOAD_H_ @}*/
