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

#include "builder.h"

ENUM(builder_part_names, BUILD_FROM_FILE, BUILD_END,
	"BUILD_FROM_FILE",
	"BUILD_FROM_FD",
	"BUILD_AGENT_SOCKET",
	"BUILD_BLOB_ASN1_DER",
	"BUILD_BLOB_PEM",
	"BUILD_BLOB_PGP",
	"BUILD_BLOB_DNSKEY",
	"BUILD_PASSPHRASE",
	"BUILD_PASSPHRASE_CALLBACK",
	"BUILD_KEY_SIZE",
	"BUILD_SIGNING_KEY",
	"BUILD_SIGNING_CERT",
	"BUILD_PUBLIC_KEY",
	"BUILD_SUBJECT",
	"BUILD_SUBJECT_ALTNAMES",
	"BUILD_ISSUER",
	"BUILD_ISSUER_ALTNAMES",
	"BUILD_NOT_BEFORE_TIME",
	"BUILD_NOT_AFTER_TIME",
	"BUILD_SERIAL",
	"BUILD_DIGEST_ALG",
	"BUILD_IETF_GROUP_ATTR",
	"BUILD_CA_CERT",
	"BUILD_CERT",
	"BUILD_CRL_DISTRIBUTION_POINTS",
	"BUILD_OCSP_ACCESS_LOCATIONS",
	"BUILD_PATHLEN",
	"BUILD_X509_FLAG",
	"BUILD_REVOKED_ENUMERATOR",
	"BUILD_SMARTCARD_KEYID",
	"BUILD_SMARTCARD_PIN",
	"BUILD_RSA_MODULUS",
	"BUILD_RSA_PUB_EXP",
	"BUILD_RSA_PRIV_EXP",
	"BUILD_RSA_PRIME1",
	"BUILD_RSA_PRIME2",
	"BUILD_RSA_EXP1",
	"BUILD_RSA_EXP2",
	"BUILD_RSA_COEFF",
	"BUILD_END",
);

