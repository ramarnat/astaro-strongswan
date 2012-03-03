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
 * @defgroup transform_substructure transform_substructure
 * @{ @ingroup payloads
 */

#ifndef TRANSFORM_SUBSTRUCTURE_H_
#define TRANSFORM_SUBSTRUCTURE_H_

typedef struct transform_substructure_t transform_substructure_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/transform_attribute.h>
#include <utils/linked_list.h>
#include <crypto/diffie_hellman.h>
#include <crypto/signers/signer.h>
#include <crypto/prfs/prf.h>
#include <crypto/crypters/crypter.h>
#include <config/proposal.h>


/**
 * IKEv1 Value for a transform payload.
 */
#define TRANSFORM_TYPE_VALUE 3

/**
 * Length of the transform substructure header in bytes.
 */
#define TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH 8


/**
 * Class representing an IKEv2- TRANSFORM SUBSTRUCTURE.
 *
 * The TRANSFORM SUBSTRUCTURE format is described in RFC section 3.3.2.
 */
struct transform_substructure_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Creates an iterator of stored transform_attribute_t objects.
	 *
	 * When deleting an transform attribute using this iterator,
	 * the length of this transform substructure has to be refreshed
	 * by calling get_length().
	 *
	 * @param forward 		iterator direction (TRUE: front to end)
	 * @return				created iterator_t object.
	 */
	iterator_t * (*create_transform_attribute_iterator) (
								transform_substructure_t *this, bool forward);

	/**
	 * Adds a transform_attribute_t object to this object.
	 *
	 * @param proposal  transform_attribute_t object to add
	 */
	void (*add_transform_attribute) (transform_substructure_t *this,
									 transform_attribute_t *attribute);

	/**
	 * Sets the next_payload field of this substructure
	 *
	 * If this is the last transform, next payload field is set to 0,
	 * otherwise to 3
	 *
	 * @param is_last	When TRUE, next payload field is set to 0, otherwise to 3
	 */
	void (*set_is_last_transform) (transform_substructure_t *this, bool is_last);

	/**
	 * Checks if this is the last transform.
	 *
	 * @return 			TRUE if this is the last Transform, FALSE otherwise
	 */
	bool (*get_is_last_transform) (transform_substructure_t *this);

	/**
	 * Sets transform type of the current transform substructure.
	 *
	 * @param type		type value to set
	 */
	void (*set_transform_type) (transform_substructure_t *this, u_int8_t type);

	/**
	 * get transform type of the current transform.
	 *
	 * @return 			Transform type of current transform substructure.
	 */
	u_int8_t (*get_transform_type) (transform_substructure_t *this);

	/**
	 * Sets transform id of the current transform substructure.
	 *
	 * @param id		transform id to set
	 */
	void (*set_transform_id) (transform_substructure_t *this, u_int16_t id);

	/**
	 * get transform id of the current transform.
	 *
	 * @return 			Transform id of current transform substructure.
	 */
	u_int16_t (*get_transform_id) (transform_substructure_t *this);

	/**
	 * get transform id of the current transform.
	 *
	 * @param key_length	The key length is written to this location
	 * @return
	 * 						- SUCCESS if a key length attribute is contained
	 * 						- FAILED if no key length attribute is part of this
	 * 						  transform or key length uses more then 16 bit!
	 */
	status_t (*get_key_length) (transform_substructure_t *this,
								u_int16_t *key_length);

	/**
	 * Clones an transform_substructure_t object.
	 *
	 * @return		cloned transform_substructure_t object
	 */
	transform_substructure_t* (*clone) (transform_substructure_t *this);

	/**
	 * Destroys an transform_substructure_t object.
	 */
	void (*destroy) (transform_substructure_t *this);
};

/**
 * Creates an empty transform_substructure_t object.
 *
 * @return			created transform_substructure_t object
 */
transform_substructure_t *transform_substructure_create(void);

/**
 * Creates an empty transform_substructure_t object.
 *
 * The key length is used for the transport types ENCRYPTION_ALGORITHM,
 * PSEUDO_RANDOM_FUNCTION, INTEGRITY_ALGORITHM. For all
 * other transport types the key_length parameter is not used
 *
 * @param transform_type	type of transform to create
 * @param transform_id		transform id specifying the specific algorithm of a transform type
 * @param key_length		Key length for key lenght attribute
 * @return					transform_substructure_t object
 */
transform_substructure_t *transform_substructure_create_type(
						transform_type_t transform_type, u_int16_t transform_id,
						u_int16_t key_length);

#endif /** TRANSFORM_SUBSTRUCTURE_H_ @}*/
