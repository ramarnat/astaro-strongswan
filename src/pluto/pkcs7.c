/* Support of PKCS#7 data structures
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2002-2009 Andreas Steffen
 *
 * HSR Hochschule fuer Technik Rapperswil, Switzerland
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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <library.h>
#include <debug.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>
#include <crypto/rngs/rng.h>
#include <crypto/crypters/crypter.h>
#include <credentials/certificates/x509.h>

#include "pkcs7.h"

const contentInfo_t empty_contentInfo = {
	OID_UNKNOWN , /* type */
	{ NULL, 0 }   /* content */
};

/**
 * ASN.1 definition of the PKCS#7 ContentInfo type
 */
static const asn1Object_t contentInfoObjects[] = {
	{ 0, "contentInfo",                     ASN1_SEQUENCE,     ASN1_NONE          }, /*  0 */
	{ 1,   "contentType",                   ASN1_OID,          ASN1_BODY          }, /*  1 */
	{ 1,   "content",                       ASN1_CONTEXT_C_0,  ASN1_OPT|ASN1_BODY }, /*  2 */
	{ 1,   "end opt",                       ASN1_EOC,          ASN1_END           }, /*  3 */
	{ 0, "exit",                            ASN1_EOC,          ASN1_EXIT          }
};
#define PKCS7_INFO_TYPE         1
#define PKCS7_INFO_CONTENT      2

/**
 * ASN.1 definition of the PKCS#7 signedData type
 */
static const asn1Object_t signedDataObjects[] = {
	{ 0, "signedData",                      ASN1_SEQUENCE,     ASN1_NONE          }, /*  0 */
	{ 1,   "version",                       ASN1_INTEGER,      ASN1_BODY          }, /*  1 */
	{ 1,   "digestAlgorithms",              ASN1_SET,          ASN1_LOOP          }, /*  2 */
	{ 2,     "algorithm",                   ASN1_EOC,          ASN1_RAW           }, /*  3 */
	{ 1,   "end loop",                      ASN1_EOC,          ASN1_END           }, /*  4 */
	{ 1,   "contentInfo",                   ASN1_EOC,          ASN1_RAW           }, /*  5 */
	{ 1,   "certificates",                  ASN1_CONTEXT_C_0,  ASN1_OPT|ASN1_LOOP }, /*  6 */
	{ 2,      "certificate",                ASN1_SEQUENCE,     ASN1_OBJ           }, /*  7 */
	{ 1,   "end opt or loop",               ASN1_EOC,          ASN1_END           }, /*  8 */
	{ 1,   "crls",                          ASN1_CONTEXT_C_1,  ASN1_OPT|ASN1_LOOP }, /*  9 */
	{ 2,      "crl",                        ASN1_SEQUENCE,     ASN1_OBJ           }, /* 10 */
	{ 1,   "end opt or loop",               ASN1_EOC,          ASN1_END           }, /* 11 */
	{ 1,   "signerInfos",                   ASN1_SET,          ASN1_LOOP          }, /* 12 */
	{ 2,     "signerInfo",                  ASN1_SEQUENCE,     ASN1_NONE          }, /* 13 */
	{ 3,       "version",                   ASN1_INTEGER,      ASN1_BODY          }, /* 14 */
	{ 3,       "issuerAndSerialNumber",     ASN1_SEQUENCE,     ASN1_BODY          }, /* 15 */
	{ 4,         "issuer",                  ASN1_SEQUENCE,     ASN1_OBJ           }, /* 16 */
	{ 4,         "serial",                  ASN1_INTEGER,      ASN1_BODY          }, /* 17 */
	{ 3,       "digestAlgorithm",           ASN1_EOC,          ASN1_RAW           }, /* 18 */
	{ 3,       "authenticatedAttributes",   ASN1_CONTEXT_C_0,  ASN1_OPT|ASN1_OBJ  }, /* 19 */
	{ 3,       "end opt",                   ASN1_EOC,          ASN1_END           }, /* 20 */
	{ 3,       "digestEncryptionAlgorithm", ASN1_EOC,          ASN1_RAW           }, /* 21 */
	{ 3,       "encryptedDigest",           ASN1_OCTET_STRING, ASN1_BODY          }, /* 22 */
	{ 3,       "unauthenticatedAttributes", ASN1_CONTEXT_C_1,  ASN1_OPT           }, /* 23 */
	{ 3,       "end opt",                   ASN1_EOC,          ASN1_END           }, /* 24 */
	{ 1,   "end loop",                      ASN1_EOC,          ASN1_END           }, /* 25 */
	{ 0, "exit",                            ASN1_EOC,          ASN1_EXIT          }
};
#define PKCS7_SIGNED_VERSION             1
#define PKCS7_DIGEST_ALG                 3
#define PKCS7_SIGNED_CONTENT_INFO        5
#define PKCS7_SIGNED_CERT                7
#define PKCS7_SIGNER_INFO               13
#define PKCS7_SIGNER_INFO_VERSION       14
#define PKCS7_SIGNED_ISSUER             16
#define PKCS7_SIGNED_SERIAL_NUMBER      17
#define PKCS7_DIGEST_ALGORITHM          18
#define PKCS7_AUTH_ATTRIBUTES           19
#define PKCS7_DIGEST_ENC_ALGORITHM      21
#define PKCS7_ENCRYPTED_DIGEST          22

/**
 * ASN.1 definition of the PKCS#7 envelopedData type
 */
static const asn1Object_t envelopedDataObjects[] = {
	{ 0, "envelopedData",                  ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
	{ 1,   "version",                      ASN1_INTEGER,      ASN1_BODY }, /*  1 */
	{ 1,   "recipientInfos",               ASN1_SET,          ASN1_LOOP }, /*  2 */
	{ 2,     "recipientInfo",              ASN1_SEQUENCE,     ASN1_BODY }, /*  3 */
	{ 3,       "version",                  ASN1_INTEGER,      ASN1_BODY }, /*  4 */
	{ 3,       "issuerAndSerialNumber",    ASN1_SEQUENCE,     ASN1_BODY }, /*  5 */
	{ 4,         "issuer",                 ASN1_SEQUENCE,     ASN1_OBJ  }, /*  6 */
	{ 4,         "serial",                 ASN1_INTEGER,      ASN1_BODY }, /*  7 */
	{ 3,       "encryptionAlgorithm",      ASN1_EOC,          ASN1_RAW  }, /*  8 */
	{ 3,       "encryptedKey",             ASN1_OCTET_STRING, ASN1_BODY }, /*  9 */
	{ 1,   "end loop",                     ASN1_EOC,          ASN1_END  }, /* 10 */
	{ 1,   "encryptedContentInfo",         ASN1_SEQUENCE,     ASN1_OBJ  }, /* 11 */
	{ 2,     "contentType",                ASN1_OID,          ASN1_BODY }, /* 12 */
	{ 2,     "contentEncryptionAlgorithm", ASN1_EOC,          ASN1_RAW  }, /* 13 */
	{ 2,     "encryptedContent",           ASN1_CONTEXT_S_0,  ASN1_BODY }, /* 14 */
	{ 0, "exit",                           ASN1_EOC,          ASN1_EXIT }
};
#define PKCS7_ENVELOPED_VERSION          1
#define PKCS7_RECIPIENT_INFO_VERSION     4
#define PKCS7_ISSUER                     6
#define PKCS7_SERIAL_NUMBER              7
#define PKCS7_ENCRYPTION_ALG             8
#define PKCS7_ENCRYPTED_KEY              9
#define PKCS7_CONTENT_TYPE              12
#define PKCS7_CONTENT_ENC_ALGORITHM     13
#define PKCS7_ENCRYPTED_CONTENT         14
#define PKCS7_ENVELOPED_ROOF            15

/**
 * Parse PKCS#7 ContentInfo object
 */
bool pkcs7_parse_contentInfo(chunk_t blob, u_int level0, contentInfo_t *cInfo)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool success = FALSE;

	parser = asn1_parser_create(contentInfoObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		if (objectID == PKCS7_INFO_TYPE)
		{
			cInfo->type = asn1_known_oid(object);
			if (cInfo->type < OID_PKCS7_DATA
			||  cInfo->type > OID_PKCS7_ENCRYPTED_DATA)
			{
				DBG1(DBG_LIB, "unknown pkcs7 content type");
				goto end;
			}
		}
		else if (objectID == PKCS7_INFO_CONTENT)
		{
			cInfo->content = object;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	return success;
}

/**
 * Parse a PKCS#7 signedData object
 */
bool pkcs7_parse_signedData(chunk_t blob, contentInfo_t *data,
							linked_list_t *certs,
							chunk_t *attributes, certificate_t *cacert)
{
	asn1_parser_t *parser;
	chunk_t object;
	int digest_alg = OID_UNKNOWN;
	int enc_alg    = OID_UNKNOWN;
	int signerInfos = 0;
	int version;
	int objectID;
	bool success = FALSE;

	contentInfo_t cInfo = empty_contentInfo;
	chunk_t encrypted_digest = chunk_empty;

	if (!pkcs7_parse_contentInfo(blob, 0, &cInfo))
	{
		return FALSE;
	}
	if (cInfo.type != OID_PKCS7_SIGNED_DATA)
	{
		DBG1(DBG_LIB, "pkcs7 content type is not signedData");
		return FALSE;
	}

	parser = asn1_parser_create(signedDataObjects, cInfo.content);
	parser->set_top_level(parser, 2);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser);

		switch (objectID)
		{
		case PKCS7_SIGNED_VERSION:
			version = object.len ? (int)*object.ptr : 0;
			DBG2(DBG_LIB, "  v%d", version);
			break;
		case PKCS7_DIGEST_ALG:
			digest_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
			break;
		case PKCS7_SIGNED_CONTENT_INFO:
			if (data != NULL)
			{
				pkcs7_parse_contentInfo(object, level, data);
			}
			break;
		case PKCS7_SIGNED_CERT:
			{
				certificate_t *cert;

				DBG2(DBG_LIB, "  parsing pkcs7-wrapped certificate");
				cert = lib->creds->create(lib->creds,
								  		  CRED_CERTIFICATE, CERT_X509,
								  		  BUILD_BLOB_ASN1_DER, object,
								  		  BUILD_END);
				if (cert)
				{
					certs->insert_last(certs, cert);
				}
			}
			break;
		case PKCS7_SIGNER_INFO:
			signerInfos++;
			DBG2(DBG_LIB, "  signer #%d", signerInfos);
			break;
		case PKCS7_SIGNER_INFO_VERSION:
			version = object.len ? (int)*object.ptr : 0;
			DBG2(DBG_LIB, "  v%d", version);
			break;
		case PKCS7_SIGNED_ISSUER:
			{
				identification_t *issuer = identification_create_from_encoding(
													ID_DER_ASN1_DN, object);
				DBG2(DBG_LIB, "  \"%Y\"", issuer);
				issuer->destroy(issuer);
				break;
			}
		case PKCS7_AUTH_ATTRIBUTES:
			if (attributes != NULL)
			{
				*attributes = object;
				*attributes->ptr = ASN1_SET;
			}
			break;
		case PKCS7_DIGEST_ALGORITHM:
			digest_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
			break;
		case PKCS7_DIGEST_ENC_ALGORITHM:
			enc_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
			break;
		case PKCS7_ENCRYPTED_DIGEST:
			encrypted_digest = object;
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);
	if (!success)
	{
		return FALSE;
	}

	/* check the signature only if a cacert is available */
	if (cacert != NULL)
	{
		public_key_t *key;
		signature_scheme_t scheme;

		scheme = signature_scheme_from_oid(digest_alg);
		if (scheme == SIGN_UNKNOWN)
		{
			DBG1(DBG_LIB, "unsupported signature scheme");
			return FALSE;
		}
		if (signerInfos == 0)
		{
			DBG1(DBG_LIB, "no signerInfo object found");
			return FALSE;
		}
		else if (signerInfos > 1)
		{
			DBG1(DBG_LIB, "more than one signerInfo object found");
			return FALSE;
		}
		if (attributes->ptr == NULL)
		{
			DBG1(DBG_LIB, "no authenticatedAttributes object found");
			return FALSE;
		}
		if (enc_alg != OID_RSA_ENCRYPTION)
		{
			DBG1(DBG_LIB, "only RSA digest encryption supported");
			return FALSE;
		}

		/* verify the signature */
		key = cacert->get_public_key(cacert);
		if (key == NULL)
		{
			DBG1(DBG_LIB, "no public key found in CA certificate");
			return FALSE;
		}
		if (key->verify(key, scheme, *attributes, encrypted_digest))
		{
			DBG2(DBG_LIB, "signature is valid");
		}
		else
		{
			DBG1(DBG_LIB, "invalid signature");
			success = FALSE;
		}
		key->destroy(key);
	}
	return success;
}

/**
 * Parse a PKCS#7 envelopedData object
 */
bool pkcs7_parse_envelopedData(chunk_t blob, chunk_t *data,
							   chunk_t serialNumber,
							   private_key_t *key)
{
	asn1_parser_t *parser;
	chunk_t object;
	chunk_t iv                = chunk_empty;
	chunk_t symmetric_key     = chunk_empty;
	chunk_t encrypted_content = chunk_empty;

	crypter_t *crypter = NULL;

	int enc_alg         = OID_UNKNOWN;
	int content_enc_alg = OID_UNKNOWN;
	int version;
	int objectID;
	bool success = FALSE;

	contentInfo_t cInfo = empty_contentInfo;
	*data = chunk_empty;

	if (!pkcs7_parse_contentInfo(blob, 0, &cInfo))
	{
		goto failed;
	}
	if (cInfo.type != OID_PKCS7_ENVELOPED_DATA)
	{
		DBG1(DBG_LIB, "pkcs7 content type is not envelopedData");
		goto failed;
	}

	parser = asn1_parser_create(envelopedDataObjects, cInfo.content);
	parser->set_top_level(parser, 2);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser);

		switch (objectID)
		{
		case PKCS7_ENVELOPED_VERSION:
			version = object.len ? (int)*object.ptr : 0;
			DBG2(DBG_LIB, "  v%d", version);
			if (version != 0)
			{
				DBG1(DBG_LIB, "envelopedData version is not 0");
				goto end;
			}
			break;
		case PKCS7_RECIPIENT_INFO_VERSION:
			version = object.len ? (int)*object.ptr : 0;
			DBG2(DBG_LIB, "  v%d", version);
			if (version != 0)
			{
				DBG1(DBG_LIB, "recipient info version is not 0");
				goto end;
			}
			break;
		case PKCS7_ISSUER:
			{
				identification_t *issuer = identification_create_from_encoding(
													ID_DER_ASN1_DN, object);
				DBG2(DBG_LIB, "  \"%Y\"", issuer);
				issuer->destroy(issuer);
				break;
			}
		case PKCS7_SERIAL_NUMBER:
			if (!chunk_equals(serialNumber, object))
			{
				DBG1(DBG_LIB, "serial numbers do not match");
				goto end;
			}
			break;
		case PKCS7_ENCRYPTION_ALG:
			enc_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
			if (enc_alg != OID_RSA_ENCRYPTION)
			{
				DBG1(DBG_LIB, "only rsa encryption supported");
				goto end;
			}
			break;
		case PKCS7_ENCRYPTED_KEY:
			if (!key->decrypt(key, object, &symmetric_key))
			{
				DBG1(DBG_LIB, "symmetric key could not be decrypted with rsa");
				goto end;
			}
			DBG4(DBG_LIB, "symmetric key %B", &symmetric_key);
			break;
		case PKCS7_CONTENT_TYPE:
			if (asn1_known_oid(object) != OID_PKCS7_DATA)
			{
				 DBG1(DBG_LIB, "encrypted content not of type pkcs7 data");
				 goto end;
			}
			break;
		case PKCS7_CONTENT_ENC_ALGORITHM:
			content_enc_alg = asn1_parse_algorithmIdentifier(object, level, &iv);

			if (content_enc_alg == OID_UNKNOWN)
			{
				DBG1(DBG_LIB, "unknown content encryption algorithm");
				goto end;
			}
			if (!asn1_parse_simple_object(&iv, ASN1_OCTET_STRING, level+1, "IV"))
			{
				DBG1(DBG_LIB, "IV could not be parsed");
				goto end;
			}
			break;
		case PKCS7_ENCRYPTED_CONTENT:
			encrypted_content = object;
			break;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	if (!success)
	{
		goto failed;
	}
	success = FALSE;

	/* decrypt the content */
	{
		encryption_algorithm_t alg;
		size_t key_size;
		crypter_t *crypter;

		alg = encryption_algorithm_from_oid(content_enc_alg, &key_size);
		if (alg == ENCR_UNDEFINED)
		{
			DBG1(DBG_LIB, "unsupported content encryption algorithm");
			goto failed;
		}
		crypter = lib->crypto->create_crypter(lib->crypto, alg, key_size);
		if (crypter == NULL)
		{
			DBG1(DBG_LIB, "crypter %N not available", encryption_algorithm_names, alg);
			goto failed;
		}
		if (symmetric_key.len != crypter->get_key_size(crypter))
		{
			DBG1(DBG_LIB, "symmetric key length %d is wrong", symmetric_key.len);
			goto failed;
		}
		if (iv.len != crypter->get_block_size(crypter))
		{
			DBG1(DBG_LIB, "IV length %d is wrong", iv.len);
			goto failed;
		}
		crypter->set_key(crypter, symmetric_key);
		crypter->decrypt(crypter, encrypted_content, iv, data);
		DBG4(DBG_LIB, "decrypted content with padding: %B", data);
	}

	/* remove the padding */
	{
		u_char *pos = data->ptr + data->len - 1;
		u_char pattern = *pos;
		size_t padding = pattern;

		if (padding > data->len)
		{
			DBG1(DBG_LIB, "padding greater than data length");
			goto failed;
		}
		data->len -= padding;

		while (padding-- > 0)
		{
			if (*pos-- != pattern)
			{
				DBG1(DBG_LIB, "wrong padding pattern");
				goto failed;
			}
		}
	}
	success = TRUE;

failed:
	DESTROY_IF(crypter);
	chunk_clear(&symmetric_key);
	if (!success)
	{
		free(data->ptr);
	}
	return success;
}

/**
 * @brief Builds a contentType attribute
 *
 * @return ASN.1 encoded contentType attribute
 */
chunk_t pkcs7_contentType_attribute(void)
{
	return asn1_wrap(ASN1_SEQUENCE, "mm",
						asn1_build_known_oid(OID_PKCS9_CONTENT_TYPE),
						asn1_wrap(ASN1_SET, "m",
							asn1_build_known_oid(OID_PKCS7_DATA)));
}

/**
 * @brief Builds a messageDigest attribute
 *
 *
 * @param[in] blob content to create digest of
 * @param[in] digest_alg digest algorithm to be used
 * @return ASN.1 encoded messageDigest attribute
 *
 */
chunk_t pkcs7_messageDigest_attribute(chunk_t content, int digest_alg)
{
	chunk_t digest;
	hash_algorithm_t hash_alg;
	hasher_t *hasher;

	hash_alg = hasher_algorithm_from_oid(digest_alg);
	hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
	hasher->allocate_hash(hasher, content, &digest);
	hasher->destroy(hasher);

	return asn1_wrap(ASN1_SEQUENCE, "mm",
				asn1_build_known_oid(OID_PKCS9_MESSAGE_DIGEST),
				asn1_wrap(ASN1_SET, "m",
					asn1_wrap(ASN1_OCTET_STRING, "m", digest)));
}

/**
 * build a DER-encoded contentInfo object
 */
static chunk_t pkcs7_build_contentInfo(contentInfo_t *cInfo)
{
	return (cInfo->content.ptr) ?
				asn1_wrap(ASN1_SEQUENCE, "mm",
					asn1_build_known_oid(cInfo->type),
					asn1_simple_object(ASN1_CONTEXT_C_0, cInfo->content)) :
				asn1_build_known_oid(cInfo->type);
}

/**
 * build issuerAndSerialNumber object
 */
chunk_t pkcs7_build_issuerAndSerialNumber(certificate_t *cert)
{
	identification_t *issuer = cert->get_issuer(cert);
	x509_t *x509 = (x509_t*)cert;

	return asn1_wrap(ASN1_SEQUENCE, "cm",
					 issuer->get_encoding(issuer),
					 asn1_integer("c", x509->get_serial(x509)));
}

/**
 * create a signed pkcs7 contentInfo object
 */
chunk_t pkcs7_build_signedData(chunk_t data, chunk_t attributes,
							   certificate_t *cert, int digest_alg,
							   private_key_t *key)
{
	contentInfo_t pkcs7Data, signedData;
	chunk_t authenticatedAttributes = chunk_empty;
	chunk_t encryptedDigest = chunk_empty;
	chunk_t signerInfo, cInfo, signature;
	signature_scheme_t scheme = signature_scheme_from_oid(digest_alg);

	if (attributes.ptr)
	{
		if (key->sign(key, scheme, attributes, &signature))
		{
			encryptedDigest = asn1_wrap(ASN1_OCTET_STRING, "m", signature);
			authenticatedAttributes = chunk_clone(attributes);
			*authenticatedAttributes.ptr = ASN1_CONTEXT_C_0;
		}
	}
	else if (data.ptr)
	{
		if (key->sign(key, scheme, data, &signature))
		{
			encryptedDigest = asn1_wrap(ASN1_OCTET_STRING, "m", signature);
		}
	}
	signerInfo = asn1_wrap(ASN1_SEQUENCE, "cmmmmm"
				, ASN1_INTEGER_1
				, pkcs7_build_issuerAndSerialNumber(cert)
				, asn1_algorithmIdentifier(digest_alg)
				, authenticatedAttributes
				, asn1_algorithmIdentifier(OID_RSA_ENCRYPTION)
				, encryptedDigest);

	pkcs7Data.type    = OID_PKCS7_DATA;
	pkcs7Data.content = (data.ptr == NULL)? chunk_empty
				: asn1_simple_object(ASN1_OCTET_STRING, data);

	signedData.type = OID_PKCS7_SIGNED_DATA;
	signedData.content = asn1_wrap(ASN1_SEQUENCE, "cmmmm"
				, ASN1_INTEGER_1
				, asn1_wrap(ASN1_SET, "m", asn1_algorithmIdentifier(digest_alg))
				, pkcs7_build_contentInfo(&pkcs7Data)
				, asn1_wrap(ASN1_CONTEXT_C_0, "m", cert->get_encoding(cert))
				, asn1_wrap(ASN1_SET, "m", signerInfo));

	cInfo = pkcs7_build_contentInfo(&signedData);
	DBG3(DBG_LIB, "signedData %B", &cInfo);

	free(pkcs7Data.content.ptr);
	free(signedData.content.ptr);
	return cInfo;
}

/**
 * create a symmetrically encrypted pkcs7 contentInfo object
 */
chunk_t pkcs7_build_envelopedData(chunk_t data, certificate_t *cert, int enc_alg)
{
	encryption_algorithm_t alg;
	size_t alg_key_size;
	chunk_t symmetricKey, protectedKey, iv, in, out;
	crypter_t *crypter;

	alg = encryption_algorithm_from_oid(enc_alg, &alg_key_size);
	crypter = lib->crypto->create_crypter(lib->crypto, alg,
										  alg_key_size/BITS_PER_BYTE);
	if (crypter == NULL)
	{
		DBG1(DBG_LIB, "crypter for %N not available", encryption_algorithm_names, alg);
		return chunk_empty;
	}

	/* generate a true random symmetric encryption key and a pseudo-random iv */
	{
		rng_t *rng;

		rng = lib->crypto->create_rng(lib->crypto, RNG_TRUE);
		rng->allocate_bytes(rng, crypter->get_key_size(crypter), &symmetricKey);
		DBG4(DBG_LIB, "symmetric encryption key %B", &symmetricKey);
		rng->destroy(rng);

		rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		rng->allocate_bytes(rng, crypter->get_block_size(crypter), &iv);
		DBG4(DBG_LIB, "initialization vector: %B", &iv);
		rng->destroy(rng);
	}

	/* pad the data to a multiple of the block size */
	{
		size_t block_size = crypter->get_block_size(crypter);
		size_t padding = block_size - data.len % block_size;

		in.len = data.len + padding;
		in.ptr = malloc(in.len);

		DBG2(DBG_LIB, "padding %u bytes of data to multiple block size of %u bytes",
			 data.len, in.len);

		/* copy data */
		memcpy(in.ptr, data.ptr, data.len);
		/* append padding */
		memset(in.ptr + data.len, padding, padding);
	}
	DBG3(DBG_LIB, "padded unencrypted data %B", &in);

	/* symmetric encryption of data object */
	crypter->set_key(crypter, symmetricKey);
	crypter->encrypt(crypter, in, iv, &out);
	crypter->destroy(crypter);
	chunk_clear(&in);
    DBG3(DBG_LIB, "encrypted data %B", &out);

	/* protect symmetric key by public key encryption */
	{
		public_key_t *key = cert->get_public_key(cert);

		if (key == NULL)
		{
			DBG1(DBG_LIB, "public key not found in encryption certificate");
			chunk_clear(&symmetricKey);
			chunk_free(&iv);
			chunk_free(&out);
			return chunk_empty;
		}
		key->encrypt(key, symmetricKey, &protectedKey);
		key->destroy(key);
	}

	/* build pkcs7 enveloped data object */
	{

		chunk_t contentEncryptionAlgorithm = asn1_wrap(ASN1_SEQUENCE, "mm"
					, asn1_build_known_oid(enc_alg)
					, asn1_simple_object(ASN1_OCTET_STRING, iv));

		chunk_t encryptedContentInfo = asn1_wrap(ASN1_SEQUENCE, "mmm"
					, asn1_build_known_oid(OID_PKCS7_DATA)
					, contentEncryptionAlgorithm
					, asn1_wrap(ASN1_CONTEXT_S_0, "m", out));

		chunk_t encryptedKey = asn1_wrap(ASN1_OCTET_STRING, "m"
					, protectedKey);

		chunk_t recipientInfo = asn1_wrap(ASN1_SEQUENCE, "cmmm"
					, ASN1_INTEGER_0
					, pkcs7_build_issuerAndSerialNumber(cert)
					, asn1_algorithmIdentifier(OID_RSA_ENCRYPTION)
					, encryptedKey);

		chunk_t cInfo;
		contentInfo_t envelopedData;

		envelopedData.type = OID_PKCS7_ENVELOPED_DATA;
		envelopedData.content = asn1_wrap(ASN1_SEQUENCE, "cmm"
					, ASN1_INTEGER_0
					, asn1_wrap(ASN1_SET, "m", recipientInfo)
					, encryptedContentInfo);

		cInfo = pkcs7_build_contentInfo(&envelopedData);
		DBG3(DBG_LIB, "envelopedData %B", &cInfo);

		chunk_free(&envelopedData.content);
		chunk_free(&iv);
		chunk_clear(&symmetricKey);
		return cInfo;
	}
}
