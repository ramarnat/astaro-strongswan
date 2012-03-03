/* FreeS/WAN ISAKMP VendorID
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
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

#ifndef _VENDOR_H_
#define _VENDOR_H_

enum known_vendorid {
/* 1 - 100 : Implementation names */
  VID_OPENPGP                   =  1,
  VID_KAME_RACOON               =  2,
  VID_MS_NT5                    =  3,
  VID_SSH_SENTINEL              =  4,
  VID_SSH_SENTINEL_1_1          =  5,
  VID_SSH_SENTINEL_1_2          =  6,
  VID_SSH_SENTINEL_1_3          =  7,
  VID_SSH_SENTINEL_1_4          =  8,
  VID_SSH_SENTINEL_1_4_1        =  9,
  VID_SSH_IPSEC_1_1_0           = 10,
  VID_SSH_IPSEC_1_1_1           = 11,
  VID_SSH_IPSEC_1_1_2           = 12,
  VID_SSH_IPSEC_1_2_1           = 13,
  VID_SSH_IPSEC_1_2_2           = 14,
  VID_SSH_IPSEC_2_0_0           = 15,
  VID_SSH_IPSEC_2_1_0           = 16,
  VID_SSH_IPSEC_2_1_1           = 17,
  VID_SSH_IPSEC_2_1_2           = 18,
  VID_SSH_IPSEC_3_0_0           = 19,
  VID_SSH_IPSEC_3_0_1           = 20,
  VID_SSH_IPSEC_4_0_0           = 21,
  VID_SSH_IPSEC_4_0_1           = 22,
  VID_SSH_IPSEC_4_1_0           = 23,
  VID_SSH_IPSEC_4_2_0           = 24,
  VID_CISCO_UNITY               = 25,
  VID_CISCO3K                   = 26,
  VID_CISCO_IOS                 = 27,
  VID_TIMESTEP                  = 28,
  VID_SAFENET                   = 29,
  VID_MACOSX                    = 30,
  VID_NCP_SERVER                = 31,
  VID_NCP_CLIENT                = 32,
  VID_VISTA_AUTHIP              = 33,
  VID_VISTA_AUTHIP2             = 34,
  VID_VISTA_AUTHIP3             = 35,

  VID_STRONGSWAN                = 36,

  VID_STRONGSWAN_2_8_0          = 37,
  VID_STRONGSWAN_2_8_1          = 38,
  VID_STRONGSWAN_2_8_2          = 39,
  VID_STRONGSWAN_2_8_3          = 40,
  VID_STRONGSWAN_2_8_4          = 41,
  VID_STRONGSWAN_2_8_5          = 42,
  VID_STRONGSWAN_2_8_6          = 43,
  VID_STRONGSWAN_2_8_7          = 44,
  VID_STRONGSWAN_2_8_8          = 45,
  VID_STRONGSWAN_2_8_9          = 46,
  VID_STRONGSWAN_2_8_10         = 47,
  VID_STRONGSWAN_2_8_11         = 48,

  VID_STRONGSWAN_4_1_0          = 88,
  VID_STRONGSWAN_4_1_1          = 89,
  VID_STRONGSWAN_4_1_2          = 90,
  VID_STRONGSWAN_4_1_3          = 91,
  VID_STRONGSWAN_4_1_4          = 92,
  VID_STRONGSWAN_4_1_5          = 93,
  VID_STRONGSWAN_4_1_6          = 94,
  VID_STRONGSWAN_4_1_7          = 95,
  VID_STRONGSWAN_4_1_8          = 96,
  VID_STRONGSWAN_4_1_9          = 97,
  VID_STRONGSWAN_4_1_10         = 98,
  VID_STRONGSWAN_4_1_11         = 99,
  VID_STRONGSWAN_4_2_0          =100,
  VID_STRONGSWAN_4_2_1          =101,
  VID_STRONGSWAN_4_2_2          =102,
  VID_STRONGSWAN_4_2_3          =103,
  VID_STRONGSWAN_4_2_4          =104,
  VID_STRONGSWAN_4_2_5          =105,
  VID_STRONGSWAN_4_2_6          =106,
  VID_STRONGSWAN_4_2_7          =107,
  VID_STRONGSWAN_4_2_8          =108,
  VID_STRONGSWAN_4_2_9          =109,
  VID_STRONGSWAN_4_2_10         =110,
  VID_STRONGSWAN_4_2_11         =111,
  VID_STRONGSWAN_4_2_12         =112,
  VID_STRONGSWAN_4_2_13         =113,
  VID_STRONGSWAN_4_2_14         =114,
  VID_STRONGSWAN_4_2_15         =115,
  VID_STRONGSWAN_4_2_16         =116,
  VID_STRONGSWAN_4_2_17         =117,
  VID_STRONGSWAN_4_3_0          =118,
  VID_STRONGSWAN_4_3_1          =119,
  VID_STRONGSWAN_4_3_2          =120,
  VID_STRONGSWAN_4_3_3          =121,
  VID_STRONGSWAN_4_3_4          =122,
  VID_STRONGSWAN_4_3_5          =123,

  /* 101 - 200 : NAT-Traversal */
  VID_NATT_STENBERG_01          =151,
  VID_NATT_STENBERG_02          =152,
  VID_NATT_HUTTUNEN             =153,
  VID_NATT_HUTTUNEN_ESPINUDP    =154,
  VID_NATT_IETF_00              =155,
  VID_NATT_IETF_02_N            =156,
  VID_NATT_IETF_02              =157,
  VID_NATT_IETF_03              =158,
  VID_NATT_RFC                  =159,

  /* 201 - 300 : Misc */
  VID_MISC_XAUTH                =201,
  VID_MISC_DPD                  =202,
  VID_MISC_HEARTBEAT_NOTIFY     =203,
  VID_MISC_FRAGMENTATION        =204,
  VID_INITIAL_CONTACT           =205,
  VID_CISCO3K_FRAGMENTATION     =206
};

void init_vendorid(void);
void free_vendorid(void);

struct msg_digest;
void handle_vendorid (struct msg_digest *md, const char *vid, size_t len);

bool out_vendorid (u_int8_t np, pb_stream *outs, enum known_vendorid vid);

#endif /* _VENDOR_H_ */

