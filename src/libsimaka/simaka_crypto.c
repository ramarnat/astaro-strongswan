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

#include "simaka_crypto.h"

#include <daemon.h>

/** length of the k_encr key */
#define KENCR_LEN 16
/** length of the k_auth key */
#define KAUTH_LEN 16
/** length of the MSK */
#define MSK_LEN 64
/** length of the EMSK */
#define EMSK_LEN 64

typedef struct private_simaka_crypto_t private_simaka_crypto_t;

/**
 * Private data of an simaka_crypto_t object.
 */
struct private_simaka_crypto_t {

	/**
	 * Public simaka_crypto_t interface.
	 */
	simaka_crypto_t public;

	/**
	 * signer to create/verify AT_MAC
	 */
	signer_t *signer;

	/**
	 * crypter to encrypt/decrypt AT_ENCR_DATA
	 */
	crypter_t *crypter;

	/**
	 * hasher used in key derivation
	 */
	hasher_t *hasher;

	/**
	 * PRF function used in key derivation
	 */
	prf_t *prf;

	/**
	 * Random number generator to generate nonces
	 */
	rng_t *rng;

	/**
	 * Have k_encr/k_auth been derived?
	 */
	bool derived;
};

/**
 * Implementation of simaka_crypto_t.get_signer
 */
static signer_t* get_signer(private_simaka_crypto_t *this)
{
	return this->derived ? this->signer : NULL;
}

/**
 * Implementation of simaka_crypto_t.get_crypter
 */
static crypter_t* get_crypter(private_simaka_crypto_t *this)
{
	return this->derived ? this->crypter : NULL;
}

/**
 * Implementation of simaka_crypto_t.get_rng
 */
static rng_t* get_rng(private_simaka_crypto_t *this)
{
	return this->rng;
}

/**
 * Implementation of simaka_crypto_t.derive_keys_full
 */
static chunk_t derive_keys_full(private_simaka_crypto_t *this,
								identification_t *id, chunk_t data, chunk_t *mk)
{
	chunk_t str, msk, k_encr, k_auth;
	int i;

	/* For SIM: MK = SHA1(Identity|n*Kc|NONCE_MT|Version List|Selected Version)
	 * For AKA: MK = SHA1(Identity|IK|CK) */
	this->hasher->get_hash(this->hasher, id->get_encoding(id), NULL);
	this->hasher->allocate_hash(this->hasher, data, mk);
	DBG3(DBG_IKE, "MK %B", mk);

	/* K_encr | K_auth | MSK | EMSK = prf() | prf() | prf() | prf() */
	this->prf->set_key(this->prf, *mk);
	str = chunk_alloca(this->prf->get_block_size(this->prf) * 3);
	for (i = 0; i < 3; i++)
	{
		this->prf->get_bytes(this->prf, chunk_empty, str.ptr + str.len / 3 * i);
	}

	k_encr = chunk_create(str.ptr, KENCR_LEN);
	k_auth = chunk_create(str.ptr + KENCR_LEN, KAUTH_LEN);
	msk = chunk_create(str.ptr + KENCR_LEN + KAUTH_LEN, MSK_LEN);
	DBG3(DBG_IKE, "K_encr %B\nK_auth %B\nMSK %B", &k_encr, &k_auth, &msk);

	this->signer->set_key(this->signer, k_auth);
	this->crypter->set_key(this->crypter, k_encr);

	charon->sim->key_hook(charon->sim, k_encr, k_auth);

	this->derived = TRUE;
	return chunk_clone(msk);
}

/**
 * Implementation of simaka_crypto_t.derive_keys_reauth
 */
static void derive_keys_reauth(private_simaka_crypto_t *this, chunk_t mk)
{
	chunk_t str, k_encr, k_auth;
	int i;

	/* K_encr | K_auth = prf() | prf() */
	this->prf->set_key(this->prf, mk);
	str = chunk_alloca(this->prf->get_block_size(this->prf) * 2);
	for (i = 0; i < 2; i++)
	{
		this->prf->get_bytes(this->prf, chunk_empty, str.ptr + str.len / 2 * i);
	}
	k_encr = chunk_create(str.ptr, KENCR_LEN);
	k_auth = chunk_create(str.ptr + KENCR_LEN, KAUTH_LEN);
	DBG3(DBG_IKE, "K_encr %B\nK_auth %B", &k_encr, &k_auth);

	this->signer->set_key(this->signer, k_auth);
	this->crypter->set_key(this->crypter, k_encr);

	charon->sim->key_hook(charon->sim, k_encr, k_auth);

	this->derived = TRUE;
}

/**
 * Implementation of simaka_crypto_t.derive_keys_reauth_msk
 */
static chunk_t derive_keys_reauth_msk(private_simaka_crypto_t *this,
									  identification_t *id, chunk_t counter,
									  chunk_t nonce_s, chunk_t mk)
{
	char xkey[HASH_SIZE_SHA1];
	chunk_t str, msk;
	int i;

	this->hasher->get_hash(this->hasher, id->get_encoding(id), NULL);
	this->hasher->get_hash(this->hasher, counter, NULL);
	this->hasher->get_hash(this->hasher, nonce_s, NULL);
	this->hasher->get_hash(this->hasher, mk, xkey);

	/* MSK | EMSK = prf() | prf() | prf() | prf() */
	this->prf->set_key(this->prf, chunk_create(xkey, sizeof(xkey)));
	str = chunk_alloca(this->prf->get_block_size(this->prf) * 2);
	for (i = 0; i < 2; i++)
	{
		this->prf->get_bytes(this->prf, chunk_empty, str.ptr + str.len / 2 * i);
	}
	msk = chunk_create(str.ptr, MSK_LEN);
	DBG3(DBG_IKE, "MSK %B", &msk);

	return chunk_clone(msk);
}

/**
 * Implementation of simaka_crypto_t.clear_keys
 */
static void clear_keys(private_simaka_crypto_t *this)
{
	this->derived = FALSE;
}

/**
 * Implementation of simaka_crypto_t.destroy.
 */
static void destroy(private_simaka_crypto_t *this)
{
	DESTROY_IF(this->rng);
	DESTROY_IF(this->hasher);
	DESTROY_IF(this->prf);
	DESTROY_IF(this->signer);
	DESTROY_IF(this->crypter);
	free(this);
}

/**
 * See header
 */
simaka_crypto_t *simaka_crypto_create()
{
	private_simaka_crypto_t *this = malloc_thing(private_simaka_crypto_t);

	this->public.get_signer = (signer_t*(*)(simaka_crypto_t*))get_signer;
	this->public.get_crypter = (crypter_t*(*)(simaka_crypto_t*))get_crypter;
	this->public.get_rng = (rng_t*(*)(simaka_crypto_t*))get_rng;
	this->public.derive_keys_full = (chunk_t(*)(simaka_crypto_t*, identification_t *id, chunk_t data, chunk_t *mk))derive_keys_full;
	this->public.derive_keys_reauth = (void(*)(simaka_crypto_t*, chunk_t mk))derive_keys_reauth;
	this->public.derive_keys_reauth_msk = (chunk_t(*)(simaka_crypto_t*, identification_t *id, chunk_t counter, chunk_t nonce_s, chunk_t mk))derive_keys_reauth_msk;
	this->public.clear_keys = (void(*)(simaka_crypto_t*))clear_keys;
	this->public.destroy = (void(*)(simaka_crypto_t*))destroy;

	this->derived = FALSE;
	this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	this->hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	this->prf = lib->crypto->create_prf(lib->crypto, PRF_FIPS_SHA1_160);
	this->signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_SHA1_128);
	this->crypter = lib->crypto->create_crypter(lib->crypto, ENCR_AES_CBC, 16);
	if (!this->rng || !this->hasher || !this->prf ||
		!this->signer || !this->crypter)
	{
		DBG1(DBG_IKE, "unable to use EAP-SIM, missing algorithms");
		destroy(this);
		return NULL;
	}
	return &this->public;
}

