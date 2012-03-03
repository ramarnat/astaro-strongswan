/*
 * Astaro User Authentication plugin for XAUTH
 *
 * Author: Heiko Hund <hhund@astaro.com>
 * Copyright (C) 2011 Astaro GmbH & Co. KG
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

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <iconv.h>

#include <keys.h>

#include "xauth_aua_verifier.h"

#define AUA_PORT      15723
#define AUA_FACILITY  "ipsec"
#define AUA_TIMEOUT   5000/*ms*/

typedef struct private_xauth_aua_verifier_t private_xauth_aua_verifier_t;

struct private_xauth_aua_verifier_t {
	xauth_verifier_t public;
};

METHOD(xauth_verifier_t, verify_secret, bool,
	private_xauth_aua_verifier_t *this, connection_t *c, chunk_t password)
{
	static char buf[512];
	static char user[64], pass[64];
	static char peer_address[ADDRTOT_BUF];
	char *in_ptr, *out_ptr;
	size_t in_bytes, out_bytes;
	size_t user_len, pass_len;
	struct pollfd pfds[1];
	struct sockaddr_in addr;
	bool res = FALSE;
	const char *conn_ref, *conn_ref_end;
	iconv_t icd;
	ssize_t len;
	int fd = -1;

	identification_t *vpn_id = c->spd.that.id;
	identification_t *username = c->xauth_identity;

	conn_ref = strstr(c->name, "REF_");
	if (conn_ref == NULL)
		goto out;
	conn_ref_end = strrchr(c->name, '_');
	if (conn_ref_end == NULL)
		goto out;

	/* Connect to AUA daemon */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(AUA_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		goto out;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		goto out;

	/* convert XAUTH data to UTF-8 */
	icd = iconv_open("UTF-8", "ISO-8859-1");
	if (icd == (iconv_t) -1)
		goto out;

	in_ptr = (char*) username->get_encoding(username).ptr;
	in_bytes = username->get_encoding(username).len;
	out_ptr = user;
	out_bytes = sizeof(user);
	if (iconv(icd, &in_ptr, &in_bytes, &out_ptr, &out_bytes) == -1)
		goto out_iconv;
	user_len = sizeof(user) - out_bytes;

	in_ptr = (char*) password.ptr;
	in_bytes = password.len;
	out_ptr = pass;
	out_bytes = sizeof(pass);
	if (iconv(icd, &in_ptr, &in_bytes, &out_ptr, &out_bytes) == -1)
		goto out_iconv;
	pass_len = sizeof(pass) - out_bytes;

	/* Send request to AUA daemon */
	addrtot(&c->spd.that.host_addr, 0, peer_address, sizeof(peer_address));
	len = snprintf(buf, sizeof(buf),
				   "%s\r\n%.*s\r\n%.*s\r\n%s\r\n%.*s\r\n%N:%#Y\r\n\r\n",
				   AUA_FACILITY, user_len, user, pass_len, pass,
				   peer_address, conn_ref_end - conn_ref, conn_ref,
				   id_type_names, vpn_id->get_type(vpn_id), vpn_id);

	if (len < 0 || len >= sizeof(buf))
		goto out_iconv;

	while (write(fd, buf, len) == -1 && errno == EINTR)
		;

	/* Read response from AUA daemon */
	pfds[0].fd = fd;
	pfds[0].events = POLLIN;

	while (poll(pfds, 1, AUA_TIMEOUT) == -1 && errno == EINTR)
		;

	if ((pfds[0].revents & POLLIN) == 0)
		goto out_iconv;

	do {
		len = read(fd, buf, sizeof(buf));
	}
	while (len == -1 && errno == EINTR);

	/* Check for "OK" response */
	if (len >= 2 && strncmp(buf, "OK", 2) == 0)
		res = TRUE;

out_iconv:
	iconv_close(icd);
out:
	close(fd);

	return res;
}

METHOD(xauth_verifier_t, destroy, void, private_xauth_aua_verifier_t *this)
{
	free(this);
}

xauth_verifier_t *xauth_aua_verifier_create()
{
	private_xauth_aua_verifier_t *this;

	INIT(this,
		.public = {
			.verify_secret = _verify_secret,
			.destroy = _destroy,
		 }
	);

	return &this->public;
}
