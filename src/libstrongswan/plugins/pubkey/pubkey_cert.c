/*
 * Copyright (C) 2008 Martin Willi
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

#include "pubkey_cert.h"

#include <debug.h>

typedef struct private_pubkey_cert_t private_pubkey_cert_t;

/**
 * private data of pubkey_cert
 */
struct private_pubkey_cert_t {

	/**
	 * public functions
	 */
	pubkey_cert_t public;

	/**
	 * wrapped public key
	 */
	public_key_t *key;

	/**
	 * dummy issuer id, ID_ANY
	 */
	identification_t *issuer;

	/**
	 * subject, ID_KEY_ID of the public key
	 */
	identification_t *subject;

	/**
	 * reference count
	 */
	refcount_t ref;
};

/**
 * Implementation of certificate_t.get_type
 */
static certificate_type_t get_type(private_pubkey_cert_t *this)
{
	return CERT_TRUSTED_PUBKEY;
}

/**
 * Implementation of certificate_t.get_subject
 */
static identification_t* get_subject(private_pubkey_cert_t *this)
{
	return this->subject;
}

/**
 * Implementation of certificate_t.get_issuer
 */
static identification_t* get_issuer(private_pubkey_cert_t *this)
{
	return this->issuer;
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_subject(private_pubkey_cert_t *this,
							  identification_t *subject)
{
	if (subject->get_type(subject) == ID_KEY_ID)
	{
		key_encoding_type_t type;
		chunk_t fingerprint;

		for (type = 0; type < KEY_ENCODING_MAX; type++)
		{
			if (this->key->get_fingerprint(this->key, type, &fingerprint) &&
				chunk_equals(fingerprint, subject->get_encoding(subject)))
			{
				return ID_MATCH_PERFECT;
			}
		}
	}
	return ID_MATCH_NONE;
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_issuer(private_pubkey_cert_t *this,
							 identification_t *issuer)
{
	return ID_MATCH_NONE;
}

/**
 * Implementation of certificate_t.equals.
 */
static bool equals(private_pubkey_cert_t *this, certificate_t *other)
{
	public_key_t *other_key;

	other_key = other->get_public_key(other);
	if (other_key)
	{
		if (public_key_equals(this->key, other_key))
		{
			other_key->destroy(other_key);
			return TRUE;
		}
		other_key->destroy(other_key);
	}
	return FALSE;
}

/**
 * Implementation of certificate_t.issued_by
 */
static bool issued_by(private_pubkey_cert_t *this, certificate_t *issuer)
{
	return equals(this, issuer);
}

/**
 * Implementation of certificate_t.get_public_key
 */
static public_key_t* get_public_key(private_pubkey_cert_t *this)
{
	this->key->get_ref(this->key);
	return this->key;
}

/**
 * Implementation of certificate_t.get_validity.
 */
static bool get_validity(private_pubkey_cert_t *this, time_t *when,
						 time_t *not_before, time_t *not_after)
{
	if (not_before)
	{
		*not_before = 0;
	}
	if (not_after)
	{
		*not_after = ~0;
	}
	return TRUE;
}

/**
 * Implementation of certificate_t.get_encoding.
 */
static chunk_t get_encoding(private_pubkey_cert_t *this)
{
	chunk_t encoding;

	if (this->key->get_encoding(this->key, KEY_PUB_ASN1_DER, &encoding))
	{
		return encoding;
	}
	return chunk_empty;
}

/**
 * Implementation of certificate_t.get_ref
 */
static private_pubkey_cert_t* get_ref(private_pubkey_cert_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of pubkey_cert_t.destroy
 */
static void destroy(private_pubkey_cert_t *this)
{
	if (ref_put(&this->ref))
	{
		this->subject->destroy(this->subject);
		this->issuer->destroy(this->issuer);
		this->key->destroy(this->key);
		free(this);
	}
}

/*
 * see header file
 */
static pubkey_cert_t *pubkey_cert_create(public_key_t *key)
{
	private_pubkey_cert_t *this = malloc_thing(private_pubkey_cert_t);
	chunk_t fingerprint;

	this->public.interface.get_type = (certificate_type_t (*)(certificate_t *this))get_type;
	this->public.interface.get_subject = (identification_t* (*)(certificate_t *this))get_subject;
	this->public.interface.get_issuer = (identification_t* (*)(certificate_t *this))get_issuer;
	this->public.interface.has_subject = (id_match_t (*)(certificate_t*, identification_t *subject))has_subject;
	this->public.interface.has_issuer = (id_match_t (*)(certificate_t*, identification_t *issuer))has_issuer;
	this->public.interface.issued_by = (bool (*)(certificate_t *this, certificate_t *issuer))issued_by;
	this->public.interface.get_public_key = (public_key_t* (*)(certificate_t *this))get_public_key;
	this->public.interface.get_validity = (bool (*)(certificate_t*, time_t *when, time_t *, time_t*))get_validity;
	this->public.interface.get_encoding = (chunk_t (*)(certificate_t*))get_encoding;
	this->public.interface.equals = (bool (*)(certificate_t*, certificate_t *other))equals;
	this->public.interface.get_ref = (certificate_t* (*)(certificate_t *this))get_ref;
	this->public.interface.destroy = (void (*)(certificate_t *this))destroy;

	this->ref = 1;
	this->key = key;
	this->issuer = identification_create_from_encoding(ID_ANY, chunk_empty);
	if (key->get_fingerprint(key, KEY_ID_PUBKEY_INFO_SHA1, &fingerprint))
	{
		this->subject = identification_create_from_encoding(ID_KEY_ID, fingerprint);
	}
	else
	{
		this->subject = identification_create_from_encoding(ID_ANY, chunk_empty);
	}

	return &this->public;
}

/**
 * See header.
 */
pubkey_cert_t *pubkey_cert_wrap(certificate_type_t type, va_list args)
{
	public_key_t *key = NULL;
	chunk_t blob = chunk_empty;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_PUBLIC_KEY:
				key = va_arg(args, public_key_t*);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (key)
	{
		key->get_ref(key);
	}
	else if (blob.ptr)
	{
		key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
								 BUILD_BLOB_ASN1_DER, blob, BUILD_END);
	}
	if (key)
	{
		return pubkey_cert_create(key);
	}
	return NULL;
}

