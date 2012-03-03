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

#include "x509.h"

ENUM(x509_flag_names, X509_NONE, X509_IP_ADDR_BLOCKS,
	"X509_NONE",
	"X509_CA",
	"X509_AA",
	"X509_OCSP_SIGNER",
	"X509_SERVER_AUTH",
	"X509_CLIENT_AUTH",
	"X509_SELF_SIGNED",
	"X509_IP_ADDR_BLOCKS",
);

