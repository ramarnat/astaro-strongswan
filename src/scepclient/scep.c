/**
 * @file scep.c
 * @brief SCEP specific functions
 *
 * Contains functions to build SCEP request's and to parse SCEP reply's.
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include <string.h>
#include <stdlib.h>

#include <freeswan.h>

#include <library.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>
#include <crypto/rngs/rng.h>
#include <crypto/hashers/hasher.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/fetch.h"
#include "../pluto/log.h"

#include "scep.h"

static const chunk_t ASN1_messageType_oid = chunk_from_chars(
	0x06, 0x0A, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x02
);
static const chunk_t ASN1_senderNonce_oid = chunk_from_chars(
	0x06, 0x0A, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x05
);
static const chunk_t ASN1_transId_oid = chunk_from_chars(
	0x06, 0x0A, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x07
);

static const char *pkiStatus_values[] = { "0", "2", "3" };

static const char *pkiStatus_names[] = {
	"SUCCESS",
	"FAILURE",
	"PENDING",
	"UNKNOWN"
};

static const char *msgType_values[] = { "3", "19", "20", "21", "22" };

static const char *msgType_names[] = {
	"CertRep",
	"PKCSReq",
	"GetCertInitial",
	"GetCert",
	"GetCRL",
	"Unknown"
};

static const char *failInfo_reasons[] = {
	"badAlg - unrecognized or unsupported algorithm identifier",
	"badMessageCheck - integrity check failed",
	"badRequest - transaction not permitted or supported",
	"badTime - Message time field was not sufficiently close to the system time",
	"badCertId - No certificate could be identified matching the provided criteria"
};

const scep_attributes_t empty_scep_attributes = {
	SCEP_Unknown_MSG   , /* msgType */
	SCEP_UNKNOWN       , /* pkiStatus */
	SCEP_unknown_REASON, /* failInfo */
	{ NULL, 0 }        , /* transID */
	{ NULL, 0 }        , /* senderNonce */
	{ NULL, 0 }        , /* recipientNonce */
};

/* ASN.1 definition of the X.501 atttribute type */

static const asn1Object_t attributesObjects[] = {
	{ 0, "attributes",    ASN1_SET,       ASN1_LOOP }, /* 0 */
	{ 1,   "attribute",   ASN1_SEQUENCE,  ASN1_NONE }, /* 1 */
	{ 2,     "type",      ASN1_OID,       ASN1_BODY }, /* 2 */
	{ 2,     "values",    ASN1_SET,       ASN1_LOOP }, /* 3 */
	{ 3,       "value",   ASN1_EOC,       ASN1_RAW  }, /* 4 */
	{ 2,     "end loop",  ASN1_EOC,       ASN1_END  }, /* 5 */
	{ 0, "end loop",      ASN1_EOC,       ASN1_END  }, /* 6 */
	{ 0, "exit",          ASN1_EOC,       ASN1_EXIT	}
};
#define ATTRIBUTE_OBJ_TYPE      2
#define ATTRIBUTE_OBJ_VALUE     4

/**
 * Extract and store an attribute
 */
static bool extract_attribute(int oid, chunk_t object, u_int level,
							  scep_attributes_t *attrs)
{
	asn1_t type = ASN1_EOC;
	const char *name = "none";

	switch (oid)
	{
	case OID_PKCS9_CONTENT_TYPE:
		type = ASN1_OID;
		name = "contentType";
		break;
	case OID_PKCS9_SIGNING_TIME:
		type = ASN1_UTCTIME;
		name = "signingTime";
		break;
	case OID_PKCS9_MESSAGE_DIGEST:
		type = ASN1_OCTET_STRING;
		name = "messageDigest";
		break;
	case OID_PKI_MESSAGE_TYPE:
		type = ASN1_PRINTABLESTRING;
		name = "messageType";
		break;
	case OID_PKI_STATUS:
		type = ASN1_PRINTABLESTRING;
		name = "pkiStatus";
		break;
	case OID_PKI_FAIL_INFO:
		type = ASN1_PRINTABLESTRING;
		name = "failInfo";
		break;
	case OID_PKI_SENDER_NONCE:
		type = ASN1_OCTET_STRING;
		name = "senderNonce";
		 break;
	case OID_PKI_RECIPIENT_NONCE:
		type = ASN1_OCTET_STRING;
		name = "recipientNonce";
		break;
	case OID_PKI_TRANS_ID:
		type = ASN1_PRINTABLESTRING;
		name = "transID";
		break;
	default:
		break;
	}

	if (type == ASN1_EOC)
		return TRUE;

	if (!asn1_parse_simple_object(&object, type, level+1, name))
		return FALSE;

	switch (oid)
	{
	case OID_PKCS9_CONTENT_TYPE:
		break;
	case OID_PKCS9_SIGNING_TIME:
		break;
	case OID_PKCS9_MESSAGE_DIGEST:
		break;
	case OID_PKI_MESSAGE_TYPE:
		{
			scep_msg_t m;

			for (m = SCEP_CertRep_MSG; m < SCEP_Unknown_MSG; m++)
			{
				if (strncmp(msgType_values[m], object.ptr, object.len) == 0)
					attrs->msgType = m;
			}
			DBG(DBG_CONTROL,
				DBG_log("messageType:  %s", msgType_names[attrs->msgType])
			)
		}
		break;
	case OID_PKI_STATUS:
		{
			pkiStatus_t s;

			for (s = SCEP_SUCCESS; s < SCEP_UNKNOWN; s++)
			{
				if (strncmp(pkiStatus_values[s], object.ptr, object.len) == 0)
					attrs->pkiStatus = s;
			}
			DBG(DBG_CONTROL,
				DBG_log("pkiStatus:    %s", pkiStatus_names[attrs->pkiStatus])
			)
		}
		break;
	case OID_PKI_FAIL_INFO:
		if (object.len == 1
		&& *object.ptr >= '0' && *object.ptr <= '4')
		{
			attrs->failInfo = (failInfo_t)(*object.ptr - '0');
		}
		if (attrs->failInfo != SCEP_unknown_REASON)
			plog("failInfo:     %s", failInfo_reasons[attrs->failInfo]);
		break;
	case OID_PKI_SENDER_NONCE:
		attrs->senderNonce = object;
		break;
	case OID_PKI_RECIPIENT_NONCE:
		attrs->recipientNonce = object;
		break;
	case OID_PKI_TRANS_ID:
		attrs->transID = object;
	}
	return TRUE;
}

/**
 * Parse X.501 attributes
 */
bool parse_attributes(chunk_t blob, scep_attributes_t *attrs)
{
	asn1_parser_t *parser;
	chunk_t object;
	int oid = OID_UNKNOWN;
	int objectID;
	bool success = FALSE;

	parser = asn1_parser_create(attributesObjects, blob);
	DBG(DBG_CONTROL | DBG_PARSING,
		DBG_log("parsing attributes")
	)

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
		case ATTRIBUTE_OBJ_TYPE:
			oid = asn1_known_oid(object);
			break;
		case ATTRIBUTE_OBJ_VALUE:
			if (!extract_attribute(oid, object, parser->get_level(parser), attrs))
			{
				goto end;
			}
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	return success;
}

/**
 * Generates a unique fingerprint of the pkcs10 request
 * by computing an MD5 hash over it
 */
chunk_t scep_generate_pkcs10_fingerprint(chunk_t pkcs10)
{
	chunk_t digest = chunk_alloca(HASH_SIZE_MD5);
	hasher_t *hasher;

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
	hasher->get_hash(hasher, pkcs10, digest.ptr);
	hasher->destroy(hasher);

	return chunk_to_hex(digest, NULL, FALSE);
}

/**
 * Generate a transaction id as the MD5 hash of an public key
 * the transaction id is also used as a unique serial number
 */
void scep_generate_transaction_id(public_key_t *key, chunk_t *transID,
								  chunk_t *serialNumber)
{
	chunk_t digest = chunk_alloca(HASH_SIZE_MD5);
	chunk_t keyEncoding = chunk_empty, keyInfo;
	hasher_t *hasher;
	bool msb_set;
	u_char *pos;

	key->get_encoding(key, KEY_PUB_ASN1_DER, &keyEncoding);

	keyInfo = asn1_wrap(ASN1_SEQUENCE, "mm",
						asn1_algorithmIdentifier(OID_RSA_ENCRYPTION),
						asn1_bitstring("m", keyEncoding));

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
	hasher->get_hash(hasher, keyInfo, digest.ptr);
	hasher->destroy(hasher);
	free(keyInfo.ptr);

	/* is the most significant bit of the digest set? */
	msb_set = (*digest.ptr & 0x80) == 0x80;

	/* allocate space for the serialNumber */
	serialNumber->len = msb_set + digest.len;
	serialNumber->ptr = malloc(serialNumber->len);

	/* the serial number as the two's complement of the digest */
	pos = serialNumber->ptr;
	if (msb_set)
	{
		*pos++ = 0x00;
	}
	memcpy(pos, digest.ptr, digest.len);

	/* the transaction id is the serial number in hex format */
	transID->len = 2*digest.len;
	transID->ptr = malloc(transID->len + 1);
	datatot(digest.ptr, digest.len, 16, transID->ptr, transID->len + 1);
}

/**
 * Builds a transId attribute
 */
chunk_t scep_transId_attribute(chunk_t transID)
{
	return asn1_wrap(ASN1_SEQUENCE, "cm"
				, ASN1_transId_oid
				, asn1_wrap(ASN1_SET, "m"
					, asn1_simple_object(ASN1_PRINTABLESTRING, transID)
				  )
			  );
}

/**
 * Builds a messageType attribute
 */
chunk_t scep_messageType_attribute(scep_msg_t m)
{
	chunk_t msgType = {
		(u_char*)msgType_values[m],
		strlen(msgType_values[m])
	};

	return asn1_wrap(ASN1_SEQUENCE, "cm"
				, ASN1_messageType_oid
				, asn1_wrap(ASN1_SET, "m"
					, asn1_simple_object(ASN1_PRINTABLESTRING, msgType)
				  )
			  );
}

/**
 * Builds a senderNonce attribute
 */
chunk_t scep_senderNonce_attribute(void)
{
	const size_t nonce_len = 16;
	u_char nonce_buf[nonce_len];
	chunk_t senderNonce = { nonce_buf, nonce_len };
	rng_t *rng;

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	rng->get_bytes(rng, nonce_len, nonce_buf);
	rng->destroy(rng);

	return asn1_wrap(ASN1_SEQUENCE, "cm"
				, ASN1_senderNonce_oid
				, asn1_wrap(ASN1_SET, "m"
					, asn1_simple_object(ASN1_OCTET_STRING, senderNonce)
				  )
			  );
}

/**
 * Builds a pkcs7 enveloped and signed scep request
 */
chunk_t scep_build_request(chunk_t data, chunk_t transID, scep_msg_t msg,
						   certificate_t *enc_cert, int enc_alg,
						   certificate_t *signer_cert, int digest_alg,
						   private_key_t *private_key)
{
	chunk_t envelopedData, attributes, request;

	envelopedData = pkcs7_build_envelopedData(data, enc_cert, enc_alg);

	attributes = asn1_wrap(ASN1_SET, "mmmmm"
					, pkcs7_contentType_attribute()
					, pkcs7_messageDigest_attribute(envelopedData
						, digest_alg)
					, scep_transId_attribute(transID)
					, scep_messageType_attribute(msg)
					, scep_senderNonce_attribute());

	request = pkcs7_build_signedData(envelopedData, attributes
					, signer_cert, digest_alg, private_key);
	free(envelopedData.ptr);
	free(attributes.ptr);
	return request;
}

/**
 * Converts a binary request to base64 with 64 characters per line
 * newline and '+' characters are escaped by %0A and %2B, respectively
 */
static char* escape_http_request(chunk_t req)
{
	char *escaped_req = NULL;
	char *p1, *p2;
	int lines = 0;
	int plus  = 0;
	int n     = 0;

	/* compute and allocate the size of the base64-encoded request */
	int len = 1 + 4*((req.len + 2)/3);
	char *encoded_req = malloc(len);

	/* do the base64 conversion */
	len = datatot(req.ptr, req.len, 64, encoded_req, len);

	/* compute newline characters to be inserted every 64 characters */
	lines = (len - 2) / 64;

	/* count number of + characters to be escaped */
	p1 = encoded_req;
	while (*p1 != '\0')
	{
		if (*p1++ == '+')
			plus++;
	}

	escaped_req = malloc(len + 3*(lines + plus));

	/* escape special characters in the request */
	p1 = encoded_req;
	p2 = escaped_req;
	while (*p1 != '\0')
	{
		if (n == 64)
		{
			memcpy(p2, "%0A", 3);
			p2 += 3;
			n = 0;
		}
		if (*p1 == '+')
		{
			memcpy(p2, "%2B", 3);
			p2 += 3;
		}
		else
		{
			*p2++ = *p1;
		}
		p1++;
		n++;
	}
	*p2 = '\0';
	free(encoded_req);
	return escaped_req;
}

/**
 * Send a SCEP request via HTTP and wait for a response
 */
bool scep_http_request(const char *url, chunk_t pkcs7, scep_op_t op,
					   bool http_get_request, chunk_t *response)
{
	int len;
	status_t status;
	char *complete_url = NULL;

	/* initialize response */
	*response = chunk_empty;

	DBG(DBG_CONTROL,
		DBG_log("sending scep request to '%s'", url)
	)

	if (op == SCEP_PKI_OPERATION)
	{
		const char operation[] = "PKIOperation";

		if (http_get_request)
		{
			char *escaped_req = escape_http_request(pkcs7);

			/* form complete url */
			len = strlen(url) + 20 + strlen(operation) + strlen(escaped_req) + 1;
			complete_url = malloc(len);
			snprintf(complete_url, len, "%s?operation=%s&message=%s"
					, url, operation, escaped_req);
			free(escaped_req);

			status = lib->fetcher->fetch(lib->fetcher, complete_url, response,
										 FETCH_HTTP_VERSION_1_0,
										 FETCH_REQUEST_HEADER, "Pragma:",
										 FETCH_REQUEST_HEADER, "Host:",
										 FETCH_REQUEST_HEADER, "Accept:",
										 FETCH_END);
		}
		else /* HTTP_POST */
		{
			/* form complete url */
			len = strlen(url) + 11 + strlen(operation) + 1;
			complete_url = malloc(len);
			snprintf(complete_url, len, "%s?operation=%s", url, operation);

			status = lib->fetcher->fetch(lib->fetcher, complete_url, response,
										 FETCH_REQUEST_DATA, pkcs7,
										 FETCH_REQUEST_TYPE, "",
										 FETCH_REQUEST_HEADER, "Expect:",
										 FETCH_END);
		}
	}
	else  /* SCEP_GET_CA_CERT */
	{
		const char operation[] = "GetCACert";

		/* form complete url */
		len = strlen(url) + 32 + strlen(operation) + 1;
		complete_url = malloc(len);
		snprintf(complete_url, len, "%s?operation=%s&message=CAIdentifier"
				, url, operation);

		status = lib->fetcher->fetch(lib->fetcher, complete_url, response,
									 FETCH_END);
	}

	free(complete_url);
	return (status == SUCCESS);
}

err_t scep_parse_response(chunk_t response, chunk_t transID, contentInfo_t *data,
						  scep_attributes_t *attrs, certificate_t *signer_cert)
{
	chunk_t attributes;

	if (!pkcs7_parse_signedData(response, data, NULL, &attributes, signer_cert))
	{
		return "error parsing the scep response";
	}
	if (!parse_attributes(attributes, attrs))
	{
		return "error parsing the scep response attributes";
	}
	if (!chunk_equals(transID, attrs->transID))
	{
		return "transaction ID of scep response does not match";
	}
	return NULL;
}
