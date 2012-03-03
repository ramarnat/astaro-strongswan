/*
 * Copyright (C) JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2009 Andreas Steffen
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
 
#include "twofish_crypter.h"
#include "twofish.h"

typedef struct private_twofish_crypter_t private_twofish_crypter_t;

/**
 * Class implementing the Twofish symmetric encryption algorithm.
 * 
 * @ingroup crypters
 */
struct private_twofish_crypter_t {
	
	/**
	 * Public part of this class.
	 */
	twofish_crypter_t public;
	
	/**
	 * Twofish context
	 */
    twofish_context twofish_ctx;
	
	/**
	* Key size of this Twofish cipher object.
	*/
	u_int32_t key_size;
};

/**
 * Implementation of crypter_t.encrypt.
 */
static void encrypt(private_twofish_crypter_t *this, chunk_t data, chunk_t iv,
					chunk_t *encrypted)
{
	int pos = 0;
	u_int8_t *in, *out;
	
	if (encrypted)
	{
		*encrypted = chunk_alloc(data.len);
		out = encrypted->ptr;
	}
	else
	{
		out = data.ptr;
	}
	in = data.ptr;
	
	while ( pos < data.len)
	{
		const u_int32_t *iv_i;

		iv_i = (pos) ? (const u_int32_t*)(out - 16) :
					   (const u_int32_t*)(iv.ptr);
		*((u_int32_t *)(&out[ 0])) = iv_i[0] ^ *((const u_int32_t *)(&in[ 0]));
		*((u_int32_t *)(&out[ 4])) = iv_i[1] ^ *((const u_int32_t *)(&in[ 4]));
		*((u_int32_t *)(&out[ 8])) = iv_i[2] ^ *((const u_int32_t *)(&in[ 8]));
		*((u_int32_t *)(&out[12])) = iv_i[3] ^ *((const u_int32_t *)(&in[12]));

		twofish_encrypt(&this->twofish_ctx, out, out);

		in  += TWOFISH_BLOCK_SIZE;
		out += TWOFISH_BLOCK_SIZE;
		pos += TWOFISH_BLOCK_SIZE;
	}
}

/**
 * Implementation of crypter_t.decrypt.
 */
static void decrypt(private_twofish_crypter_t *this, chunk_t data, chunk_t iv,
					chunk_t *decrypted)
{
	int pos = data.len - TWOFISH_BLOCK_SIZE;
	u_int8_t *in, *out;
	
	if (decrypted)
	{
		*decrypted = chunk_alloc(data.len);
		out = decrypted->ptr;
	}
	else
	{
		out = data.ptr;
	}
	in = data.ptr;
	in  += pos;
	out += pos;

	while (pos >= 0)
	{
		const u_int32_t *iv_i;

		twofish_decrypt(&this->twofish_ctx, in, out);

		iv_i = (pos) ? (const u_int32_t*)(in - 16) :
					   (const u_int32_t*)(iv.ptr);
		*((u_int32_t *)(&out[ 0])) ^= iv_i[0];
		*((u_int32_t *)(&out[ 4])) ^= iv_i[1];
		*((u_int32_t *)(&out[ 8])) ^= iv_i[2];
		*((u_int32_t *)(&out[12])) ^= iv_i[3];

		in  -= TWOFISH_BLOCK_SIZE;
		out -= TWOFISH_BLOCK_SIZE;
		pos -= TWOFISH_BLOCK_SIZE;
	}
}

/**
 * Implementation of crypter_t.get_block_size.
 */
static size_t get_block_size (private_twofish_crypter_t *this)
{
	return TWOFISH_BLOCK_SIZE;
}

/**
 * Implementation of crypter_t.get_key_size.
 */
static size_t get_key_size (private_twofish_crypter_t *this)
{
	return this->key_size;
}

/**
 * Implementation of crypter_t.set_key.
 */
static void set_key (private_twofish_crypter_t *this, chunk_t key)
{
    twofish_set_key(&this->twofish_ctx, key.ptr, key.len);
}

/**
 * Implementation of crypter_t.destroy and twofish_crypter_t.destroy.
 */
static void destroy (private_twofish_crypter_t *this)
{
	free(this);
}

/*
 * Described in header
 */
twofish_crypter_t *twofish_crypter_create(encryption_algorithm_t algo, size_t key_size)
{
	private_twofish_crypter_t *this;
	
	if (algo != ENCR_TWOFISH_CBC ||
	  !(key_size == 16 || key_size == 24 || key_size == 32))
	{
		return NULL;
	}
	
	this = malloc_thing(private_twofish_crypter_t);
	
	this->public.crypter_interface.encrypt = (void (*) (crypter_t *, chunk_t,chunk_t, chunk_t *)) encrypt;
	this->public.crypter_interface.decrypt = (void (*) (crypter_t *, chunk_t , chunk_t, chunk_t *)) decrypt;
	this->public.crypter_interface.get_block_size = (size_t (*) (crypter_t *)) get_block_size;
	this->public.crypter_interface.get_key_size = (size_t (*) (crypter_t *)) get_key_size;
	this->public.crypter_interface.set_key = (void (*) (crypter_t *,chunk_t)) set_key;
	this->public.crypter_interface.destroy = (void (*) (crypter_t *)) destroy;
	
	return &(this->public);
}
