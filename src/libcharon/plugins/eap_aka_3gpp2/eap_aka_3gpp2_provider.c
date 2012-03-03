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

#include "eap_aka_3gpp2_provider.h"

#include <daemon.h>
#include <credentials/keys/shared_key.h>

typedef struct private_eap_aka_3gpp2_provider_t private_eap_aka_3gpp2_provider_t;

/**
 * Private data of an eap_aka_3gpp2_provider_t object.
 */
struct private_eap_aka_3gpp2_provider_t {

	/**
	 * Public eap_aka_3gpp2_provider_t interface.
	 */
	eap_aka_3gpp2_provider_t public;

	/**
	 * AKA functions
	 */
	eap_aka_3gpp2_functions_t *f;

	/**
	 * time based SQN, we use the same for all peers
	 */
	char sqn[AKA_SQN_LEN];
};

/** Authentication management field */
static char amf[AKA_AMF_LEN] = {0x00, 0x01};

/**
 * Get a shared key K from the credential database
 */
bool eap_aka_3gpp2_get_k(identification_t *id, char k[AKA_K_LEN])
{
	shared_key_t *shared;
	chunk_t key;

	shared = charon->credentials->get_shared(charon->credentials,
											 SHARED_EAP, id, NULL);
	if (shared == NULL)
	{
		return FALSE;
	}
	key = shared->get_key(shared);
	memset(k, '\0', AKA_K_LEN);
	memcpy(k, key.ptr, min(key.len, AKA_K_LEN));
	shared->destroy(shared);
	return TRUE;
}

/**
 * get SQN using current time
 */
void eap_aka_3gpp2_get_sqn(char sqn[AKA_SQN_LEN], int offset)
{
	timeval_t time;

	gettimeofday(&time, NULL);
	/* set sqn to an integer containing 4 bytes seconds + 2 bytes usecs */
	time.tv_sec = htonl(time.tv_sec + offset);
	/* usec's are never larger than 0x000f423f, so we shift the 12 first bits */
	time.tv_usec = htonl(time.tv_usec << 12);
	memcpy(sqn, (char*)&time.tv_sec + sizeof(time_t) - 4, 4);
	memcpy(sqn + 4, &time.tv_usec, 2);
}

/**
 * Implementation of usim_provider_t.get_quintuplet
 */
static bool get_quintuplet(private_eap_aka_3gpp2_provider_t *this,
						   identification_t *id, char rand[AKA_RAND_LEN],
						   char xres[AKA_RES_MAX], int *xres_len,
						   char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
						   char autn[AKA_AUTN_LEN])
{
	rng_t *rng;
	char mac[AKA_MAC_LEN], ak[AKA_AK_LEN], k[AKA_K_LEN];

	/* generate RAND: we use a registered RNG, not f0() proposed in S.S0055 */
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_IKE, "generating RAND for AKA failed");
		return FALSE;
	}
	rng->get_bytes(rng, AKA_RAND_LEN, rand);
	rng->destroy(rng);

	if (!eap_aka_3gpp2_get_k(id, k))
	{
		DBG1(DBG_IKE, "no EAP key found for %Y to authenticate with AKA", id);
		return FALSE;
	}

	DBG3(DBG_IKE, "generated rand %b", rand, AKA_RAND_LEN);
	DBG3(DBG_IKE, "using K %b", k, AKA_K_LEN);

	/* MAC */
	this->f->f1(this->f, k, rand, this->sqn, amf, mac);
	/* AK */
	this->f->f5(this->f, k, rand, ak);
	/* XRES as expected from client */
	this->f->f2(this->f, k, rand, xres);
	*xres_len = AKA_RES_MAX;
	/* AUTN = (SQN xor AK) || AMF || MAC */
	memcpy(autn, this->sqn, AKA_SQN_LEN);
	memxor(autn, ak, AKA_AK_LEN);
	memcpy(autn + AKA_SQN_LEN, amf, AKA_AMF_LEN);
	memcpy(autn + AKA_SQN_LEN + AKA_AMF_LEN, mac, AKA_MAC_LEN);
	DBG3(DBG_IKE, "AUTN %b", autn, AKA_AUTN_LEN);
	/* CK/IK */
	this->f->f3(this->f, k, rand, ck);
	this->f->f4(this->f, k, rand, ik);

	return TRUE;
}

/**
 * Implementation of usim_provider_t.resync
 */
static bool resync(private_eap_aka_3gpp2_provider_t *this,
				   identification_t *id, char rand[AKA_RAND_LEN],
				   char auts[AKA_AUTS_LEN])
{
	char *sqn, *macs;
	char aks[AKA_AK_LEN], k[AKA_K_LEN], amf[AKA_AMF_LEN], xmacs[AKA_MAC_LEN];

	if (!eap_aka_3gpp2_get_k(id, k))
	{
		DBG1(DBG_IKE, "no EAP key found for %Y to authenticate with AKA", id);
		return FALSE;
	}

	/* AUTHS = (AK xor SQN) | MAC */
	sqn = auts;
	macs = auts + AKA_SQN_LEN;
	this->f->f5star(this->f, k, rand, aks);
	memxor(sqn, aks, AKA_AK_LEN);

	/* verify XMACS, AMF of zero is used in resynchronization */
	memset(amf, 0, AKA_AMF_LEN);
	this->f->f1star(this->f, k, rand, sqn, amf, xmacs);
	if (!memeq(macs, xmacs, AKA_MAC_LEN))
	{
		DBG1(DBG_IKE, "received MACS does not match XMACS");
		DBG3(DBG_IKE, "MACS %b XMACS %b",
			 macs, AKA_MAC_LEN, xmacs, AKA_MAC_LEN);
		return FALSE;
	}
	/* update stored SQN to received SQN + 1 */
	memcpy(this->sqn, sqn, AKA_SQN_LEN);
	chunk_increment(chunk_create(this->sqn, AKA_SQN_LEN));
	return TRUE;
}

/**
 * Implementation of eap_aka_3gpp2_provider_t.destroy.
 */
static void destroy(private_eap_aka_3gpp2_provider_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_aka_3gpp2_provider_t *eap_aka_3gpp2_provider_create(
												eap_aka_3gpp2_functions_t *f)
{
	private_eap_aka_3gpp2_provider_t *this = malloc_thing(private_eap_aka_3gpp2_provider_t);

	this->public.provider.get_triplet = (bool(*)(sim_provider_t*, identification_t *id, char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN]))return_false;
	this->public.provider.get_quintuplet = (bool(*)(sim_provider_t*, identification_t *id, char rand[AKA_RAND_LEN], char xres[AKA_RES_MAX], int *xres_len, char ck[AKA_CK_LEN], char ik[AKA_IK_LEN], char autn[AKA_AUTN_LEN]))get_quintuplet;
	this->public.provider.resync = (bool(*)(sim_provider_t*, identification_t *id, char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]))resync;
	this->public.provider.is_pseudonym = (identification_t*(*)(sim_provider_t*, identification_t *id))return_null;
	this->public.provider.gen_pseudonym = (identification_t*(*)(sim_provider_t*, identification_t *id))return_null;
	this->public.provider.is_reauth = (identification_t*(*)(sim_provider_t*, identification_t *id, char [HASH_SIZE_SHA1], u_int16_t *counter))return_null;
	this->public.provider.gen_reauth = (identification_t*(*)(sim_provider_t*, identification_t *id, char mk[HASH_SIZE_SHA1]))return_null;
	this->public.destroy = (void(*)(eap_aka_3gpp2_provider_t*))destroy;

	this->f = f;
	/* use an offset to accept clock skew between client/server without resync */
	eap_aka_3gpp2_get_sqn(this->sqn, 180);

	return &this->public;
}

