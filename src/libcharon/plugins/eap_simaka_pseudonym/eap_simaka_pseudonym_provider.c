/*
 * Copyright (C) 2009 Martin Willi
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

#include "eap_simaka_pseudonym_provider.h"

#include <utils/hashtable.h>

typedef struct private_eap_simaka_pseudonym_provider_t private_eap_simaka_pseudonym_provider_t;

/**
 * Private data of an eap_simaka_pseudonym_provider_t object.
 */
struct private_eap_simaka_pseudonym_provider_t {

	/**
	 * Public eap_simaka_pseudonym_provider_t interface.
	 */
	eap_simaka_pseudonym_provider_t public;

	/**
	 * Permanent -> pseudonym mappings
	 */
	hashtable_t *pseudonym;

	/**
	 * Reverse pseudonym -> permanent mappings
	 */
	hashtable_t *permanent;

	/**
	 * RNG for pseudonyms/reauth identities
	 */
	rng_t *rng;
};

/**
 * hashtable hash function
 */
static u_int hash(identification_t *key)
{
	return chunk_hash(key->get_encoding(key));
}

/**
 * hashtable equals function
 */
static bool equals(identification_t *key1, identification_t *key2)
{
	return key1->equals(key1, key2);
}

/**
 * Implementation of sim_provider_t.is_pseudonym
 */
static identification_t* is_pseudonym(
			private_eap_simaka_pseudonym_provider_t *this, identification_t *id)
{
	identification_t *permanent;

	permanent = this->permanent->get(this->permanent, id);
	if (permanent)
	{
		return permanent->clone(permanent);
	}
	return NULL;
}

/**
 * Generate a random identity
 */
static identification_t *gen_identity(
								private_eap_simaka_pseudonym_provider_t *this)
{
	char buf[8], hex[sizeof(buf) * 2 + 1];

	this->rng->get_bytes(this->rng, sizeof(buf), buf);
	chunk_to_hex(chunk_create(buf, sizeof(buf)), hex, FALSE);

	return identification_create_from_string(hex);
}

/**
 * Implementation of sim_provider_t.get_pseudonym
 */
static identification_t* gen_pseudonym(
			private_eap_simaka_pseudonym_provider_t *this, identification_t *id)
{
	identification_t *pseudonym, *permanent;

	/* remove old entry */
	pseudonym = this->pseudonym->remove(this->pseudonym, id);
	if (pseudonym)
	{
		permanent = this->permanent->remove(this->permanent, pseudonym);
		if (permanent)
		{
			permanent->destroy(permanent);
		}
		pseudonym->destroy(pseudonym);
	}

	pseudonym = gen_identity(this);

	/* create new entries */
	id = id->clone(id);
	this->pseudonym->put(this->pseudonym, id, pseudonym);
	this->permanent->put(this->permanent, pseudonym, id);

	return pseudonym->clone(pseudonym);
}

/**
 * Implementation of eap_simaka_pseudonym_provider_t.destroy.
 */
static void destroy(private_eap_simaka_pseudonym_provider_t *this)
{
	enumerator_t *enumerator;
	identification_t *id;
	void *key;

	enumerator = this->pseudonym->create_enumerator(this->pseudonym);
	while (enumerator->enumerate(enumerator, &key, &id))
	{
		id->destroy(id);
	}
	enumerator->destroy(enumerator);

	enumerator = this->permanent->create_enumerator(this->permanent);
	while (enumerator->enumerate(enumerator, &key, &id))
	{
		id->destroy(id);
	}
	enumerator->destroy(enumerator);

	this->pseudonym->destroy(this->pseudonym);
	this->permanent->destroy(this->permanent);
	this->rng->destroy(this->rng);
	free(this);
}

/**
 * See header
 */
eap_simaka_pseudonym_provider_t *eap_simaka_pseudonym_provider_create()
{
	private_eap_simaka_pseudonym_provider_t *this;

	this = malloc_thing(private_eap_simaka_pseudonym_provider_t);

	this->public.provider.get_triplet = (bool(*)(sim_provider_t*, identification_t *id, char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN]))return_false;
	this->public.provider.get_quintuplet = (bool(*)(sim_provider_t*, identification_t *id, char rand[AKA_RAND_LEN], char xres[AKA_RES_MAX], int *xres_len, char ck[AKA_CK_LEN], char ik[AKA_IK_LEN], char autn[AKA_AUTN_LEN]))return_false;
	this->public.provider.resync = (bool(*)(sim_provider_t*, identification_t *id, char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]))return_false;
	this->public.provider.is_pseudonym = (identification_t*(*)(sim_provider_t*, identification_t *id))is_pseudonym;
	this->public.provider.gen_pseudonym = (identification_t*(*)(sim_provider_t*, identification_t *id))gen_pseudonym;
	this->public.provider.is_reauth = (identification_t*(*)(sim_provider_t*, identification_t *id, char [HASH_SIZE_SHA1], u_int16_t *counter))return_null;
	this->public.provider.gen_reauth = (identification_t*(*)(sim_provider_t*, identification_t *id, char mk[HASH_SIZE_SHA1]))return_null;
	this->public.destroy = (void(*)(eap_simaka_pseudonym_provider_t*))destroy;

	this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!this->rng)
	{
		free(this);
		return NULL;
	}
	this->pseudonym = hashtable_create((void*)hash, (void*)equals, 0);
	this->permanent = hashtable_create((void*)hash, (void*)equals, 0);

	return &this->public;
}

