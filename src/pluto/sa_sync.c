/*
 * HA mode for pluto. See docs/README.HA for more information.
 * Copyright (C) 2004-2010 Astaro GmbH & Co. KG
 *                         Ulrich Weber <uweber@astaro.com>
 *                         Heiko Hund <hhund@astaro.com>
 *
 * To be done support for :
 *    - IPv6
 *    - Opportunistic Encryption
 *    - Aggressive Mode
 *    - Mode Config / XAUTH
 *    - HA VIP support
 *    - Synchronization buffer
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

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/queue.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef KLIPS
#include <signal.h>
#include <sys/time.h>   /* for select(2) */
#include <sys/types.h>  /* for select(2) */
#include <pfkeyv2.h>
#include <pfkey.h>
#include "kameipsec.h"
#endif /* KLIPS */

#include <freeswan.h>

#include "constants.h"

#include "defs.h"
#include "connections.h"
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "kernel_noklips.h"
#include "packet.h"
#include "x509.h"
#include "log.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"
#include "ike_alg.h"
#include "crypto.h"
#include "linux/netlink.h"
#include "linux/xfrm.h"
#include "nat_traversal.h"
#include "virtual.h"
#include <linux/unistd.h>
#include <linux/types.h>
#include "sa_sync.h"

ENUM(sync_msg_names, SYNC_BULK, SYNC_UPD_STATES,
	"SYNC_BULK",
	"SYNC_ADD_STATE",
	"SYNC_DEL_STATE",
	"SYNC_GET_STATE",
	"SYNC_GET_CONN",
	"SYNC_UPD_SEQ",
	"SYNC_UPD_DPD",
	"SYNC_UPD_STATES"
);

/*
 * Code for the established states serial list
 */
typedef struct ha_state {
	struct ha_state    *next;
	so_serial_t        state;
} ha_state_t;

typedef struct {
	u_int32_t  count;
	u_int32_t  checksum;
	ha_state_t *states;
} ha_states_t;
static ha_states_t ha_states = { 0, 0, NULL };

static void add_ha_state(so_serial_t state)
{
	ha_state_t *new_ha_state = malloc(sizeof(ha_state_t));
	if (!new_ha_state)
	{
		plog("HA System: unable to allocate ha_state for #%lu", state);
		return;
	}
	new_ha_state->state = state;

	/* Make a list of ascending state serials */
	ha_state_t **state_ptr = &ha_states.states;
	while (*state_ptr && (*state_ptr)->state < state)
	{
		state_ptr = &(*state_ptr)->next;
	}
	new_ha_state->next = *state_ptr;
	*state_ptr = new_ha_state;

	ha_states.count += 1;
	ha_states.checksum += state;
}

static void unlink_ha_state(ha_state_t **state_ptr)
{
	ha_state_t *ha_state = *state_ptr;
	if (ha_state != NULL)
	{
		ha_states.count -= 1;
		ha_states.checksum -= ha_state->state;
		*state_ptr = ha_state->next;
		free(ha_state);
	}
}

void del_ha_state(so_serial_t state)
{
	ha_state_t **state_ptr = &ha_states.states;
	while (*state_ptr && (*state_ptr)->state != state)
	{
		state_ptr = &(*state_ptr)->next;
	}

	if (*state_ptr == NULL)
	{
		DBG(DBG_HA, DBG_log("HA System: can not delete ha_state #%lu", state));
		return;
	}

	unlink_ha_state(state_ptr);
}


/*
 * Initialized a HA sync message buffer.
 */
static bool sync_msg_init(struct ha_sync_buffer *msg, uint8_t type, uint16_t size)
{
	struct ha_sync_hdr *sync_hdr;

	size += sizeof(*sync_hdr);
	msg->data = malloc(size);
	if (msg->data == NULL)
	{
		return FALSE;
	}
	msg->data_size = size;
	msg->length = sizeof(*sync_hdr);
	msg->cur_pos = msg->data + msg->length;

	sync_hdr = msg->data;
	sync_hdr->length = 0;
	sync_hdr->type = type;
	sync_hdr->magic = SA_SYNC_MAGIC;

	return TRUE;
}


/*
 * All HA System messages are sent with this function.
 */
static int sync_msg_send(struct ha_sync_buffer *msg, struct in_addr dst_addr)
{
	struct sockaddr_in addr;
	int sent;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = dst_addr;
	addr.sin_port = htons(SA_SYNC_PORT);

	sent = sendto(ha_sock, msg->data, msg->length, 0, (struct sockaddr *) &addr, sizeof(addr));
	if (sent != msg->length)
	{
		plog("HA System: failed to send message (%d/%d)", sent, msg->length);
		return -1;
	}

	DBG(DBG_HA, DBG_log("HA System: sent %i bytes to %s", sent, inet_ntoa(dst_addr)));
	return sent;
}


static void sync_msg_free(struct ha_sync_buffer *msg)
{
	free(msg->data);
}


static bool sync_msg_add_data(struct ha_sync_buffer *msg, const void *data, size_t length)
{
	struct ha_sync_hdr *msg_hdr;
	size_t buf_space = msg->data_size - msg->length;

	if (length > buf_space)
	{
		uint16_t new_size = 1;
		while (new_size < msg->length + length)
		{
			new_size <<= 1;
		}

		DBG(DBG_HA, DBG_log("HA System: resizing sync msg buffer to %hu bytes", new_size));

		msg->data = realloc(msg->data, new_size);
		if (msg->data == NULL)
		{
			plog("HA System: could not resize sync msg buffer");
			return FALSE;
		}
		msg->data_size = new_size;
		msg->cur_pos = msg->data + msg->length;
	}

	memcpy(msg->cur_pos, data, length);

	msg_hdr = msg->data;
	msg_hdr->length += length;
	msg->cur_pos += length;
	msg->length += length;

	return TRUE;
}


static bool sync_msg_add_sa_data(struct ha_sync_buffer *msg, sa_data_type type, const void *data, size_t length)
{
	struct sa_data *sa_data;
	struct ha_sync_hdr *msg_hdr;
	size_t sa_data_len = sizeof(*sa_data) - sizeof(sa_data->data) + length;
	size_t buf_space = msg->data_size - msg->length;

	if (sa_data_len > buf_space)
	{
		uint16_t new_size = 1;
		while (new_size < msg->length + sa_data_len)
		{
			new_size <<= 1;
		}

		DBG(DBG_HA, DBG_log("HA System: resizing sync msg buffer to %hu bytes", new_size));
		msg->data = realloc(msg->data, new_size);
		if (msg->data == NULL)
		{
			plog("HA System: could not resize sync msg buffer");
			return FALSE;
		}
		msg->data_size = new_size;
		msg->cur_pos = msg->data + msg->length;
	}
	sa_data = msg->cur_pos;
	sa_data->type = type;
	sa_data->length = length;
	memcpy(sa_data->data, data, length);

	msg_hdr = msg->data;
	msg_hdr->length += sa_data_len;
	msg->cur_pos += sa_data_len;
	msg->length += sa_data_len;

	return TRUE;
}


static void compress_state(struct state *st, struct ha_sync_buffer *msg)
{
	if (st->st_gi.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_GI, st->st_gi.ptr, st->st_gi.len);

	if (st->st_ni.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_NI, st->st_ni.ptr, st->st_ni.len);

	if (st->st_gr.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_GR, st->st_gr.ptr, st->st_gr.len);

	if (st->st_nr.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_NR, st->st_nr.ptr, st->st_nr.len);

	if (st->st_skeyid.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_SKEYID, st->st_skeyid.ptr, st->st_skeyid.len);

	if (st->st_skeyid_d.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_SKEYID_D, st->st_skeyid_d.ptr, st->st_skeyid_d.len);

	if (st->st_skeyid_a.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_SKEYID_A, st->st_skeyid_a.ptr, st->st_skeyid_a.len);

	if (st->st_skeyid_e.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_SKEYID_E, st->st_skeyid_e.ptr, st->st_skeyid_e.len);

	if (st->st_enc_key.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_ENC_KEY, st->st_enc_key.ptr, st->st_enc_key.len);

	if (st->st_shared.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_SHARED, st->st_shared.ptr, st->st_shared.len);

	if (st->st_p1isa.len > 0)
		sync_msg_add_sa_data(msg, SA_DATA_P1ISA, st->st_p1isa.ptr, st->st_p1isa.len);

	if (st->st_ipcomp.keymat_len > 0)
	{
		sync_msg_add_sa_data(msg, SA_DATA_IPCOMP_OKEY, st->st_ipcomp.our_keymat, st->st_ipcomp.keymat_len);
		sync_msg_add_sa_data(msg, SA_DATA_IPCOMP_PKEY, st->st_ipcomp.peer_keymat, st->st_ipcomp.keymat_len);
	}

	if (st->st_esp.keymat_len > 0)
	{
		sync_msg_add_sa_data(msg, SA_DATA_ESP_OKEY, st->st_esp.our_keymat, st->st_esp.keymat_len);
		sync_msg_add_sa_data(msg, SA_DATA_ESP_PKEY, st->st_esp.peer_keymat, st->st_esp.keymat_len);
	}

	if (st->st_ah.keymat_len > 0)
	{
		sync_msg_add_sa_data(msg, SA_DATA_AH_OKEY, st->st_ah.our_keymat, st->st_ah.keymat_len);
		sync_msg_add_sa_data(msg, SA_DATA_AH_PKEY, st->st_ah.peer_keymat, st->st_ah.keymat_len);
	}

	if (st->st_dh)
	{
		chunk_t dh_priv;
		st->st_dh->get_my_private_value(st->st_dh, &dh_priv);
		sync_msg_add_sa_data(msg, SA_DATA_DH_PRIVATE, dh_priv.ptr, dh_priv.len);
	}

	if (st->st_event)
	{
		struct sa_sync_event sa_event = {
			.ev_time = st->st_event->ev_time - now(),
			.ev_type = st->st_event->ev_type,
		};
		sync_msg_add_sa_data(msg, SA_DATA_EVENT, &sa_event, sizeof(sa_event));
	}

	/* Transmit static functions over wire */
	struct sa_sync_functions sa_func = {
		.encrypter = st->st_oakley.encrypter ? st->st_oakley.encrypter->algo_id : 0,
		.hasher = st->st_oakley.hasher ? st->st_oakley.hasher->algo_id : 0,
		.group = st->st_oakley.group ? st->st_oakley.group->algo_id : 0,
		.pfs_group = st->st_pfs_group ? st->st_pfs_group->algo_id : 0,
	};
	sync_msg_add_sa_data(msg, SA_DATA_OAKLEY_FUNC, &sa_func, sizeof(sa_func));
}


static void decompress_state(struct state *st, struct sa_data *sa_data_all[SA_DATA_MAX])
{
	struct sa_data *sa_data;

	if (sa_data_all[SA_DATA_GI])
	{
		sa_data = sa_data_all[SA_DATA_GI];
		st->st_gi = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_gi = chunk_empty;
	}

	if (sa_data_all[SA_DATA_NI])
	{
		sa_data = sa_data_all[SA_DATA_NI];
		st->st_ni = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_ni = chunk_empty;
	}

	if (sa_data_all[SA_DATA_GR])
	{
		sa_data = sa_data_all[SA_DATA_GR];
		st->st_gr = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_gr = chunk_empty;
	}

	if (sa_data_all[SA_DATA_NR])
	{
		sa_data = sa_data_all[SA_DATA_NR];
		st->st_nr = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_nr = chunk_empty;
	}

	if (sa_data_all[SA_DATA_SKEYID])
	{
		sa_data = sa_data_all[SA_DATA_SKEYID];
		st->st_skeyid = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_skeyid = chunk_empty;
	}

	if (sa_data_all[SA_DATA_SKEYID_D])
	{
		sa_data = sa_data_all[SA_DATA_SKEYID_D];
		st->st_skeyid_d = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_skeyid_d = chunk_empty;
	}

	if (sa_data_all[SA_DATA_SKEYID_A])
	{
		sa_data = sa_data_all[SA_DATA_SKEYID_A];
		st->st_skeyid_a = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_skeyid_a = chunk_empty;
	}

	if (sa_data_all[SA_DATA_SKEYID_E])
	{
		sa_data = sa_data_all[SA_DATA_SKEYID_E];
		st->st_skeyid_e = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_skeyid_e = chunk_empty;
	}

	if (sa_data_all[SA_DATA_ENC_KEY])
	{
		sa_data = sa_data_all[SA_DATA_ENC_KEY];
		st->st_enc_key = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_enc_key = chunk_empty;
	}

	if (sa_data_all[SA_DATA_SHARED])
	{
		sa_data = sa_data_all[SA_DATA_SHARED];
		st->st_shared = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_shared = chunk_empty;
	}

	if (sa_data_all[SA_DATA_P1ISA])
	{
		sa_data = sa_data_all[SA_DATA_P1ISA];
		st->st_p1isa = chunk_clone(chunk_create(sa_data->data, sa_data->length));
	}
	else
	{
		st->st_p1isa = chunk_empty;
	}

	if (sa_data_all[SA_DATA_IPCOMP_OKEY] && sa_data_all[SA_DATA_IPCOMP_PKEY])
	{
		sa_data = sa_data_all[SA_DATA_IPCOMP_OKEY];
		st->st_ipcomp.our_keymat = malloc(sa_data->length);
		memcpy(st->st_ipcomp.our_keymat, sa_data->data, sa_data->length);

		sa_data = sa_data_all[SA_DATA_IPCOMP_PKEY];
		st->st_ipcomp.peer_keymat = malloc(sa_data->length);
		memcpy(st->st_ipcomp.peer_keymat, sa_data->data, sa_data->length);
	}
	else
	{
		st->st_ipcomp.our_keymat = NULL;
		st->st_ipcomp.peer_keymat = NULL;
		st->st_ipcomp.keymat_len = 0;
	}

	if (sa_data_all[SA_DATA_ESP_OKEY] && sa_data_all[SA_DATA_ESP_PKEY])
	{
		sa_data = sa_data_all[SA_DATA_ESP_OKEY];
		st->st_esp.our_keymat = malloc(sa_data->length);
		memcpy(st->st_esp.our_keymat, sa_data->data, sa_data->length);

		sa_data = sa_data_all[SA_DATA_ESP_PKEY];
		st->st_esp.peer_keymat = malloc(sa_data->length);
		memcpy(st->st_esp.peer_keymat, sa_data->data, sa_data->length);
	}
	else
	{
		st->st_esp.our_keymat = NULL;
		st->st_esp.peer_keymat = NULL;
		st->st_esp.keymat_len = 0;
	}

	if (sa_data_all[SA_DATA_AH_OKEY] && sa_data_all[SA_DATA_AH_PKEY])
	{
		sa_data = sa_data_all[SA_DATA_AH_OKEY];
		st->st_ah.our_keymat = malloc(sa_data->length);
		memcpy(st->st_ah.our_keymat, sa_data->data, sa_data->length);

		sa_data = sa_data_all[SA_DATA_AH_PKEY];
		st->st_ah.peer_keymat = malloc(sa_data->length);
		memcpy(st->st_ah.peer_keymat, sa_data->data, sa_data->length);
	}
	else
	{
		st->st_ah.our_keymat = NULL;
		st->st_ah.peer_keymat = NULL;
		st->st_ah.keymat_len = 0;
	}

	if (sa_data_all[SA_DATA_EVENT])
	{
		sa_data = sa_data_all[SA_DATA_EVENT];
		struct sa_sync_event *sa_event = (struct sa_sync_event *) sa_data->data;
		event_schedule(sa_event->ev_type, sa_event->ev_time, st);
	}
	else
	{
		st->st_event = NULL;
	}

	/* DPD Event will be inserted after takeover! */
	if (sa_data_all[SA_DATA_OAKLEY_FUNC])
	{
		struct sa_sync_functions *sa_func;

		sa_data = sa_data_all[SA_DATA_OAKLEY_FUNC];
		sa_func = (struct sa_sync_functions *) sa_data->data;

		if (st->st_oakley.encrypter)
			st->st_oakley.encrypter = ike_alg_get_crypter(sa_func->encrypter);
		if (st->st_oakley.hasher)
			st->st_oakley.hasher = ike_alg_get_hasher(sa_func->hasher);
		if (st->st_oakley.group)
			st->st_oakley.group = ike_alg_get_dh_group(sa_func->group);
		if (st->st_pfs_group)
			st->st_pfs_group = ike_alg_get_dh_group(sa_func->pfs_group);
	}

	if (sa_data_all[SA_DATA_DH_PRIVATE])
	{
		sa_data = sa_data_all[SA_DATA_DH_PRIVATE];
		chunk_t xa = chunk_create(sa_data->data, sa_data->length);
		st->st_dh = lib->crypto->create_dh(lib->crypto,
										   st->st_oakley.group->algo_id, &xa);
	}
	else
	{
		st->st_dh = NULL;
	}

	/*
	 * Dirty hack: abuse of st_rpacket.len for the inbound and
	 * st_tpacket.len for the outbound replay number. The values
	 * are used in netlink_add_sa() and reset to 0 afterwards.
	 */
	if (sa_data_all[SA_DATA_SEQNO_INBOUND])
	{
		sa_data = sa_data_all[SA_DATA_SEQNO_INBOUND];
		passert(sizeof(st->st_rpacket.len) == sa_data->length);
		memcpy(&st->st_rpacket.len, sa_data->data, sa_data->length);
	}
	if (sa_data_all[SA_DATA_SEQNO_OUTBOUND])
	{
		sa_data = sa_data_all[SA_DATA_SEQNO_OUTBOUND];
		passert(sizeof(st->st_tpacket.len) == sa_data->length);
		memcpy(&st->st_tpacket.len, sa_data->data, sa_data->length);
	}
}


void do_sync_add_state(struct state *st, bool resync, struct in_addr node_addr)
{
	connection_t *c = st->st_connection;
	struct ha_sync_buffer msg;
	uint32_t seqno;

	if (!resync)
	{
		add_ha_state(st->st_serialno);
	}

	sync_msg_init(&msg, SYNC_ADD_STATE, 2048);

	DBG(DBG_HA, DBG_log("HA System: time to sync state #%lu", st->st_serialno));

	st->nat_this_port = c->spd.this.host_port;
	st->nat_that_port = c->spd.that.host_port;

	sync_msg_add_data(&msg, st, sizeof(*st));

	/* Add SPD if connection ID is roadwarrior */
	if (c->kind == CK_INSTANCE)
	{
		identification_t *his_id = c->spd.that.id;
		chunk_t id_chunk = his_id->get_encoding(his_id);
		struct sa_sync_spd spd = {
			.type = c->gw_info ? SYNC_SPD_OE : SYNC_SPD_RW,
			.instance_serial = c->instance_serial,
			.him = c->spd.that.host_addr,
			.his_port = c->spd.that.host_port,
			.his_net = c->spd.that.client,
			.his_id_type = his_id->get_type(his_id),
		};

		sync_msg_add_sa_data(&msg, SA_DATA_SPD, &spd, sizeof(spd));
		sync_msg_add_sa_data(&msg, SA_DATA_ID_ENCODED, id_chunk.ptr, id_chunk.len);
	}

	sync_msg_add_sa_data(&msg, SA_DATA_CONNAME, c->name, strlen(c->name) + 1);

	compress_state(st, &msg);

	/* If esp or ah is present and resync, include seq numbers */
	if (resync && st->st_esp.present)
	{
		seqno = 0;
		kernel_ops->update_seq(IPPROTO_ESP, st->st_esp.attrs.spi, c->spd.that.host_addr.u.v4.sin_addr.s_addr, &seqno);
		if (seqno != 0)
		{
			sync_msg_add_sa_data(&msg, SA_DATA_SEQNO_OUTBOUND, &seqno, sizeof(seqno));
		}

		seqno = 0;
		kernel_ops->update_seq(IPPROTO_ESP, st->st_esp.our_spi, c->spd.this.host_addr.u.v4.sin_addr.s_addr, &seqno);
		if (seqno != 0)
		{
			sync_msg_add_sa_data(&msg, SA_DATA_SEQNO_INBOUND, &seqno, sizeof(seqno));
		}
	}
	else if (resync && st->st_ah.present)
	{
		seqno = 0;
		kernel_ops->update_seq(IPPROTO_AH, st->st_ah.attrs.spi, c->spd.that.host_addr.u.v4.sin_addr.s_addr, &seqno);
		if(seqno != 0)
		{
			sync_msg_add_sa_data(&msg, SA_DATA_SEQNO_OUTBOUND, &seqno, sizeof(seqno));
		}

		seqno = 0;
		kernel_ops->update_seq(IPPROTO_AH, st->st_ah.our_spi, c->spd.this.host_addr.u.v4.sin_addr.s_addr, &seqno);
		if (seqno != 0)
		{
			sync_msg_add_sa_data(&msg, SA_DATA_SEQNO_INBOUND, &seqno, sizeof(seqno));
		}
	}

	sync_msg_send(&msg, node_addr);
	sync_msg_free(&msg);
}


/*
 * Request whole state table from master.
 */
void do_sync_request_bulk(void)
{
	struct ha_sync_buffer msg;
	sync_msg_init(&msg, SYNC_BULK, 0);
	sync_msg_send(&msg, ha_mcast_addr);
	sync_msg_free(&msg);
}


/*
 * Request a single state from HA master.
 */
static void do_sync_request_single(so_serial_t state, struct in_addr master_node)
{
	struct ha_sync_buffer msg;
	sync_msg_init(&msg, SYNC_GET_STATE, sizeof(state));
	sync_msg_add_data(&msg, &state, sizeof(state));
	sync_msg_send(&msg, master_node);
	sync_msg_free(&msg);
}


/*
 * Request latest states of a connection from HA master.
 */
void do_sync_request_conn(const char *conn)
{
	struct ha_sync_buffer msg;
	sync_msg_init(&msg, SYNC_GET_CONN, strlen(conn) + 1);
	sync_msg_add_data(&msg, conn, strlen(conn) + 1);
	sync_msg_send(&msg, ha_mcast_addr);
	sync_msg_free(&msg);
}


/*
 * If a sequence number update is received over XFRMG_REPLAY
 * this functions sends the update to the Slave.
 */
void do_sync_seqno(uint8_t outbound, uint8_t proto, uint32_t spi, uint32_t dst, uint32_t seqno)
{
	struct ha_sync_buffer msg;
	struct sa_sync_seq sync_seq = {
		.outbound = outbound,
		.proto = proto,
		.spi = spi,
		{ .dst = dst, },
		.seqno = seqno,
	};

	sync_msg_init(&msg, SYNC_UPD_SEQ, sizeof(sync_seq));
	sync_msg_add_data(&msg, &sync_seq, sizeof(sync_seq));
	sync_msg_send(&msg, ha_mcast_addr);
	sync_msg_free(&msg);
}


/*
 * Received sequence number updates are sent to the kernel
 * with this function. Outbound SAs will have been ha_seqdiff_out added.
 */
void do_sync_dpd(struct state *st)
{
	struct ha_sync_buffer msg;
	struct sa_sync_dpd dpd = {
		.st_serialno = st->st_serialno,
		.st_dpd_seqno = st->st_dpd_seqno,
		.st_dpd_peerseqno = st->st_dpd_peerseqno,
	};

	sync_msg_init(&msg, SYNC_UPD_DPD, sizeof(dpd));
	sync_msg_add_data(&msg, &dpd, sizeof(dpd));
	sync_msg_send(&msg, ha_mcast_addr);
	sync_msg_free(&msg);
}


void do_sync_del_state(struct state *st)
{
	struct ha_sync_buffer msg;

	DBG(DBG_HA, DBG_log("HA System: time to send delete IKE SA #%lu msg", st->st_serialno));
	
	del_ha_state(st->st_serialno);
	sync_msg_init(&msg, SYNC_DEL_STATE, sizeof(st->st_serialno));
	sync_msg_add_data(&msg, &st->st_serialno, sizeof(st->st_serialno));
	sync_msg_send(&msg, ha_mcast_addr);
	sync_msg_free(&msg);
}


void do_sync_states_update(struct in_addr node_addr)
{
	struct ha_sync_buffer msg;
	ha_state_t *ha_state;
	u_int16_t states_size;

	if (ha_states.count == 0)
	{
		return;
	}

	DBG(DBG_HA, DBG_log("HA System: time to send states update msg"));

	/* Make sure all serials fit into one UDP datagram */
	if (ha_states.count > 16300)
	{
		plog("HA System: states count exceeds limit - update canceled");
		return;
	}

	ha_state = ha_states.states;
	states_size = ha_states.count * sizeof(ha_state->state);

	sync_msg_init(&msg, SYNC_UPD_STATES, sizeof(ha_states_t) + states_size);
	sync_msg_add_data(&msg, &ha_states.count, sizeof(ha_states.count));
	sync_msg_add_data(&msg, &ha_states.checksum, sizeof(ha_states.checksum));

	while (ha_state)
	{
		sync_msg_add_data(&msg, &ha_state->state, sizeof(ha_state->state));
		ha_state = ha_state->next;
	}

	sync_msg_send(&msg, node_addr);
	sync_msg_free(&msg);
}


static void handle_add_state(void *data, int size)
{
	struct sa_data *sa_data_all[SA_DATA_MAX];
	struct sa_data *sa_data;
	struct ha_sync_buffer buf;
	struct state *sync_state = data;
	struct state *st;
	connection_t *c = NULL;
	char *name;

	if (size < sizeof(struct state))
	{
		DBG(DBG_HA, DBG_log("HA System: ignoring invalid message"));
		return;
	}

	memset(sa_data_all, 0, sizeof(sa_data_all));

	buf.length = size - sizeof(struct state);
	buf.cur_pos = data + sizeof(struct state);

	while (buf.length > 0)
	{
		size_t sa_data_len;
		sa_data = buf.cur_pos;
		sa_data_len = sizeof(*sa_data) - sizeof(sa_data->data) + sa_data->length;
		if (sa_data_len == 0)
		{
			DBG(DBG_HA, DBG_log("HA System: ignoring invalid SYNC_ADD_STATE message with zero length SA data"));
			return;
		}

		if (sa_data->type < SA_DATA_MAX)
		{
			sa_data_all[sa_data->type] = sa_data;
		}
		else
		{
			DBG(DBG_HA, DBG_log("HA System: ignoring unknown SA data of length %d", sa_data_len));
		}

		buf.cur_pos += sa_data_len;
		buf.length -= sa_data_len;
	}

	/* Just to be sure */
	st = state_with_serialno(sync_state->st_serialno);
	if (st)
	{
		delete_state(st);
	}

	st = new_state();

	passert(sa_data_all[SA_DATA_CONNAME] != NULL);
	sa_data = sa_data_all[SA_DATA_CONNAME];
	name = (char *) sa_data->data;

	if (sa_data_all[SA_DATA_SPD])
	{
		struct sa_sync_spd *spd = (struct sa_sync_spd *) sa_data_all[SA_DATA_SPD]->data;

		c = con_by_name_and_iserial(name, spd->instance_serial);
		if (c == NULL)
		{
			/* Ok create new instance */
			identification_t *his_id;

			if (spd->type != SYNC_SPD_RW)
			{
				plog("HA System: unsupported state recieved");
				return;
			}

			/* Need to get parent connection struct first */
			c = con_by_name(name, TRUE);
			if (c == NULL)
			{
				plog("HA System: connection '%s' can to be found", name);
				goto failed;
			}

			sa_data = sa_data_all[SA_DATA_ID_ENCODED];
			his_id = identification_create_from_encoding(spd->his_id_type,
									chunk_create(sa_data->data, sa_data->length));
			if (!his_id->matches(his_id, c->spd.that.id))
			{
				plog("HA System: VPN ID does not match");
				goto failed;
			}

			/* Keep instance_serial in sync. Master is one step ahead, so decrement first */
			c->instance_serial = spd->instance_serial - 1;

			c = rw_instantiate(c, &spd->him, spd->his_port, &spd->his_net, his_id);
		}
	}
	else
	{
		/* Need to get permanent connection struct */
		c = con_by_name(name, TRUE);
	}

	if (c && oriented(*c))
	{
		/*
		 * Set values of received state to safe values.
		 * The following pointers will be inserted later.
		 */
		sync_state->st_event = NULL;
		sync_state->st_dpd_event = NULL;
		sync_state->st_hashchain_next = NULL;
		sync_state->st_hashchain_prev = NULL;

		/* Data not needed on HA system */
		sync_state->st_suspended_md = NULL;
		sync_state->st_tpacket = chunk_empty;
		sync_state->st_rpacket = chunk_empty;
		sync_state->st_used_msgids = NULL;
		sync_state->st_peer_pubkey = NULL;

		*st = *sync_state;

		/* Fill state struct */
		decompress_state(st, sa_data_all);

		if (st->st_clonedfrom)
		{
			c->newest_ipsec_sa = st->st_serialno;
		}
		else
		{
			c->newest_isakmp_sa = st->st_serialno;
		}

		st->st_connection = c;

		insert_state(st);

		if ((st->nat_traversal & NAT_T_WITH_PORT_FLOATING) &&
		    (st->nat_traversal & NAT_T_DETECTED))
		{
			c->spd.this.host_port = st->nat_this_port;
			c->spd.that.host_port = st->nat_that_port;
		}

		/* Following function is needed to correct interface pointer */
		nat_traversal_change_port_lookup(NULL, st);

		if (st->st_esp.present || st->st_ah.present)
		{
			if (sa_data_all[SA_DATA_SPD])
			{
				struct sa_sync_spd *spd = (struct sa_sync_spd *) sa_data_all[SA_DATA_SPD]->data;
				c->spd.that.client = spd->his_net;
				c->spd.that.has_client_wildcard = FALSE;
				c->spd.that.has_client = subnetishost(&spd->his_net) &&
					addrinsubnet(&c->spd.that.host_addr, &spd->his_net) ?
					FALSE : TRUE;
			}

			/* L2TP magic for NAT, code from quick_inI1_outR1_tail() */
			if (st->nat_traversal && c->spd.this.port == 1701 &&
			    c->spd.that.host_port != NAT_T_IKE_FLOAT_PORT)
			{
				u_int16_t l2tp_magic_port = c->spd.that.host_port;

				c->l2tp_orig_port = c->spd.that.port;
				c->spd.that.port = l2tp_magic_port;

				setportof(htons(l2tp_magic_port), &c->spd.that.client.addr);
				c->spd.that.has_port_wildcard = FALSE;
			}

			install_ipsec_sas(st);
		}

		/* Keep used msgid list in sync */
		if (st->st_clonedfrom != 0)
		{
			struct state *isakmp_sa = state_with_serialno(st->st_clonedfrom);
			if (isakmp_sa)
			{
				reserve_msgid(isakmp_sa, st->st_msgid);
			}
		}

		DBG(DBG_HA, DBG_log("HA System: installed state #%lu", st->st_serialno));
		add_ha_state(st->st_serialno);
		return;
	}

failed:
	plog("HA system: failed to insert state. Is ipsec.conf on Master and Slave indentical?");
}


static void handle_del_state(void *serialno, int size)
{
	so_serial_t *serial = serialno;
	struct state *st;

	if (size != sizeof(*serial))
	{
		DBG(DBG_HA, DBG_log("HA System: ignoring invalid message"));
		return;
	}

	st = state_with_serialno(*serial);
	if (!st)
	{
		DBG(DBG_HA, DBG_log("HA System: failed to delete unknown state #%lu", *serial));
		return;
	}

	delete_state(st);
	DBG(DBG_HA, DBG_log("HA System: state #%lu was deleted", *serial));
}


static void handle_get_state(void *serialno, int size, struct in_addr node_addr)
{
	so_serial_t *serial = serialno;
	struct state *st;

	if (size != sizeof(*serial))
	{
		DBG(DBG_HA, DBG_log("HA System: ignoring invalid message"));
		return;
	}

	st = state_with_serialno(*serial);
	if (!st)
	{
		DBG(DBG_HA, DBG_log("HA System: failed to resync unknown state #%lu", *serial));
		return;
	}
	do_sync_add_state(st, TRUE, node_addr);
}


static void handle_get_conn(void *buffer, int size, struct in_addr node_addr)
{
	char *name = buffer;
	void send_con_states(struct state *st, void *data)
	{
		struct in_addr *node_addr = data;
		do_sync_add_state(st, TRUE, *node_addr);
	}

	if (size < 2 || name[size - 1] != '\0')
	{
		DBG(DBG_HA, DBG_log("HA System: ignoring invalid message"));
		return;
	}

	if (states_by_con_name(name, send_con_states, &node_addr) == 0)
	{
		DBG(DBG_HA, DBG_log("HA System: no states found for connection '%s'", name));
	}
}


static void handle_seq_update(void *buffer, int size)
{
	struct sa_sync_seq *sync_seq = buffer;

	if (size != sizeof(*sync_seq))
	{
		DBG(DBG_HA, DBG_log("HA System: ignoring invalid message"));
		return;
	}

	if (sync_seq->seqno == 0)
		sync_seq->seqno = 1;

	if (sync_seq->outbound)
	{
		sync_seq->seqno += ha_seqdiff_out;
		/* Overrun check */
		if(sync_seq->seqno < ha_seqdiff_out)
		{
			sync_seq->seqno = 0;
			sync_seq->seqno--;
		}
	}

	kernel_ops->update_seq(sync_seq->proto, sync_seq->spi, sync_seq->dst, &sync_seq->seqno);
}


static void handle_dpd_update(void *buffer, int size)
{
	struct sa_sync_dpd *dpd = buffer;

	if (size != sizeof(*dpd))
	{
		DBG(DBG_HA, DBG_log("HA System: ignoring invalid message"));
		return;
	}

	struct state *st = state_with_serialno(dpd->st_serialno);
	if (st)
	{
		DBG(DBG_HA, DBG_log("HA System: new DPD seq numbers for state #%lu", st->st_serialno));
		st->st_dpd_seqno = dpd->st_dpd_seqno;
		st->st_dpd_peerseqno = dpd->st_dpd_peerseqno;
	}
}


static void handle_states_update(void *buffer, int size, struct in_addr master_node)
{
	struct sa_sync_update *upd = buffer;
	ha_state_t **state_ptr = &ha_states.states;
	u_int32_t i = 0;

	if (size < sizeof(*upd) || size < upd->count * sizeof(*upd->states))
	{
		DBG(DBG_HA, DBG_log("HA System: ignoring invalid message"));
		return;
	}

	/* Return if we're already up to date */
	if (upd->count == ha_states.count && upd->checksum == ha_states.checksum)
	{
		return;
	}

	DBG(DBG_HA, DBG_log("HA System: processing state updates from master"));

	/* Compare the local states list to the one the HA master sent */
	while (i < upd->count || *state_ptr)
	{
		if (i >= upd->count)
		{
			/* HA master has no more states, delete local state */
			struct state *st = state_with_serialno((*state_ptr)->state);
			if (st == NULL)
			{
				/* Just delete the HA state */
				unlink_ha_state(state_ptr);
			}
			else
			{
				DBG(DBG_HA, DBG_log("HA System: deleting state #%lu", (*state_ptr)->state));
				delete_state(st);
			}
		}
		else if (*state_ptr == NULL)
		{
			/* No local state to compare to, request state from HA master */
			DBG(DBG_HA, DBG_log("HA System: requesting state #%lu", upd->states[i]));
			do_sync_request_single(upd->states[i++], master_node);
		}
		else if (upd->states[i] > (*state_ptr)->state)
		{
			/* We have a state HA master doensn't have */
			struct state *st = state_with_serialno((*state_ptr)->state);
			if (st == NULL)
			{
				/* Just delete the HA state */
				unlink_ha_state(state_ptr);
			}
			else
			{
				DBG(DBG_HA, DBG_log("HA System: deleting state #%lu", (*state_ptr)->state));
				delete_state(st);
			}
		}
		else if (upd->states[i] < (*state_ptr)->state)
		{
			/* HA master has state we do not have */
			DBG(DBG_HA, DBG_log("HA System: requesting state #%lu", upd->states[i]));
			do_sync_request_single(upd->states[i++], master_node);
		}
		else
		{
			/* HA master state is already installed, proceed */
			state_ptr = &(*state_ptr)->next;
			i++;
		}
	}
}


void process_sync_msg(struct ha_sync_msg *msg, struct in_addr node_addr)
{
	switch(msg->hdr.type)
	{
	case SYNC_BULK:
		if (ha_master == 1)
			state_sync_bulk(node_addr);
		break;

	case SYNC_GET_STATE:
		if (ha_master == 1)
			handle_get_state(msg->data, msg->hdr.length, node_addr);
		break;

	case SYNC_GET_CONN:
		if (ha_master == 1)
			handle_get_conn(msg->data, msg->hdr.length, node_addr);
		break;

	case SYNC_ADD_STATE:
		if (ha_master == 0)
			handle_add_state(msg->data, msg->hdr.length);
		break;

	case SYNC_DEL_STATE:
		if (ha_master == 0)
			handle_del_state(msg->data, msg->hdr.length);
		break;

	case SYNC_UPD_SEQ:
		if (ha_master == 0)
			handle_seq_update(msg->data, msg->hdr.length);
		break;

	case SYNC_UPD_DPD:
		if (ha_master == 0)
			handle_dpd_update(msg->data, msg->hdr.length);
		break;

	case SYNC_UPD_STATES:
		if (ha_master == 0)
			handle_states_update(msg->data, msg->hdr.length, node_addr);
		break;

	default:
		DBG(DBG_HA, DBG_log("HA System: ignoring message of unknown type"));
		break;
	}
}

