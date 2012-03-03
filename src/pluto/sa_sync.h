#ifndef SA_SYNC_H
#define SA_SYNC_H

#include <linux/netlink.h>
#include "linux/xfrm.h"

/* Port and Multicast address configuration */
#define SA_SYNC_PORT        501
#define SA_SYNC_MULTICAST   "224.0.0.82"

/* 8 Bit Magic Value. Increase if state struct changed */
#define SA_SYNC_MAGIC       0x55

/* Default values for seq diff synchronisation */
#define SA_SYNC_SEQDIFF_IN  256
#define SA_SYNC_SEQDIFF_OUT 4096

/* ------ End of configuration ------ */

/* SA Sync message types */
typedef enum {
	SYNC_BULK,
	SYNC_ADD_STATE,
	SYNC_DEL_STATE,
	SYNC_GET_STATE,
	SYNC_GET_CONN,
	SYNC_UPD_SEQ,
	SYNC_UPD_DPD,
	SYNC_UPD_STATES
} sync_msg_type;
extern enum_name_t *sync_msg_names;

/* SA DATA types */
typedef enum {
	SA_DATA_CONNAME,
	SA_DATA_GI,
	SA_DATA_NI,
	SA_DATA_GR,
	SA_DATA_NR,
	SA_DATA_P1ISA,
	SA_DATA_SKEYID,
	SA_DATA_SKEYID_D,
	SA_DATA_SKEYID_A,
	SA_DATA_SKEYID_E,
	SA_DATA_ENC_KEY,
	SA_DATA_SHARED,
	SA_DATA_IPCOMP_OKEY,
	SA_DATA_IPCOMP_PKEY,
	SA_DATA_ESP_OKEY,
	SA_DATA_ESP_PKEY,
	SA_DATA_AH_OKEY,
	SA_DATA_AH_PKEY,
	SA_DATA_DH_PRIVATE,
	SA_DATA_EVENT,
	SA_DATA_SPD,
	SA_DATA_ID_ENCODED,
	SA_DATA_OAKLEY_FUNC,
	SA_DATA_SEQNO_INBOUND,
	SA_DATA_SEQNO_OUTBOUND,
	SA_DATA_MAX
}  sa_data_type;

/* There can be different types of SPD entries */
#define SYNC_SPD_RW     1
#define SYNC_SPD_OE     2

#define HA_NOT_MASTER   (ha_interface && ha_master !=  1)
#define HA_INIT         (ha_interface && ha_master == -1)
#define HA_SLAVE        (ha_interface && ha_master ==  0)

struct ha_sync_buffer {
	uint16_t length;
	void     *cur_pos;
	uint16_t data_size;
	void     *data;
};

struct ha_sync_hdr {
	uint16_t    length;
	uint8_t     type;
	uint8_t     magic;
};
#define SA_SYNC_MINSIZE sizeof(struct sa_sync_hdr)

struct ha_sync_msg {
	struct ha_sync_hdr  hdr;
	uint8_t             data[1];
};

struct sa_data {
	uint8_t type;
	uint16_t length;
	uint8_t data[1];
};

struct sa_sync_seq {
	uint8_t     outbound;
	uint8_t     proto;
	uint32_t    spi;
	union {
		uint32_t    dst;
		uint32_t    dst_v6[4];
	};
	uint32_t    seqno;
};

struct sa_sync_dpd {
	so_serial_t st_serialno;
	u_int32_t   st_dpd_seqno;
	u_int32_t   st_dpd_peerseqno;
};

struct sa_sync_update {
	u_int32_t   count;
	u_int32_t   checksum;
	so_serial_t states[1];
};

struct sa_sync_event {
	time_t  ev_time;
	int     ev_type;
};

struct sa_sync_spd {
	uint8_t         type;
	unsigned long   instance_serial;
	ip_address      him;
	u_int16_t       his_port;
	ip_subnet       his_net;
	id_type_t       his_id_type;
};

struct sa_sync_functions {
	u_int16_t   encrypter;
	u_int16_t   hasher;
	u_int16_t   group;
	u_int16_t   pfs_group;
};

void del_ha_state(so_serial_t);
void do_sync_add_state(struct state *, bool, struct in_addr);
void do_sync_del_state(struct state *);
void do_sync_states_update(struct in_addr);
void do_sync_request_bulk(void);
void do_sync_request_conn(const char *);
void do_sync_seqno(uint8_t, uint8_t, uint32_t, uint32_t, uint32_t);
void do_sync_dpd(struct state *);
void process_sync_msg(struct ha_sync_msg *, struct in_addr);

/* global sa_sync variables */
extern int ha_master;
extern u_int32_t ha_seqdiff_in;
extern u_int32_t ha_seqdiff_out;
extern char *ha_interface;
extern struct in_addr ha_mcast_addr;
extern int ha_sock;

#endif
