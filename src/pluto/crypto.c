/* crypto interfaces
 * Copyright (C) 1998-2001 D. Hugh Redelmeier
 * Copyright (C) 2007-2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "crypto.h"
#include "log.h"

static struct encrypt_desc encrypt_desc_des =
{
	algo_type:       IKE_ALG_ENCRYPT,
	algo_id:         OAKLEY_DES_CBC,
	algo_next:       NULL,

	enc_blocksize:   DES_BLOCK_SIZE, 
	keydeflen:       DES_BLOCK_SIZE * BITS_PER_BYTE,
	keyminlen:       DES_BLOCK_SIZE * BITS_PER_BYTE,
	keymaxlen:       DES_BLOCK_SIZE * BITS_PER_BYTE,
};

static struct encrypt_desc encrypt_desc_3des =
{
	algo_type:       IKE_ALG_ENCRYPT,
	algo_id:         OAKLEY_3DES_CBC,
	algo_next:       NULL,

	enc_blocksize:	 DES_BLOCK_SIZE,
	keydeflen:		 DES_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	keyminlen:		 DES_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	keymaxlen:		 DES_BLOCK_SIZE * 3 * BITS_PER_BYTE,
};

#define  AES_KEY_MIN_LEN	128
#define  AES_KEY_DEF_LEN	128
#define  AES_KEY_MAX_LEN	256

static struct encrypt_desc encrypt_desc_aes =
{
	algo_type: 	     IKE_ALG_ENCRYPT,
	algo_id:   	     OAKLEY_AES_CBC,
	algo_next: 	     NULL,

	enc_blocksize: 	 AES_BLOCK_SIZE,
	keyminlen: 		 AES_KEY_MIN_LEN,
	keydeflen: 		 AES_KEY_DEF_LEN,
	keymaxlen: 		 AES_KEY_MAX_LEN,
};

#define  CAMELLIA_KEY_MIN_LEN	128
#define  CAMELLIA_KEY_DEF_LEN	128
#define  CAMELLIA_KEY_MAX_LEN	256

static struct encrypt_desc encrypt_desc_camellia =
{
	algo_type: 	     IKE_ALG_ENCRYPT,
	algo_id:   	     OAKLEY_CAMELLIA_CBC,
	algo_next: 	     NULL,

	enc_blocksize: 	 CAMELLIA_BLOCK_SIZE,
	keyminlen: 		 CAMELLIA_KEY_MIN_LEN,
	keydeflen: 		 CAMELLIA_KEY_DEF_LEN,
	keymaxlen: 		 CAMELLIA_KEY_MAX_LEN,
};

#define  BLOWFISH_KEY_MIN_LEN	128
#define  BLOWFISH_KEY_MAX_LEN	448

static struct encrypt_desc encrypt_desc_blowfish =
{
	algo_type:       IKE_ALG_ENCRYPT,
	algo_id:         OAKLEY_BLOWFISH_CBC,
	algo_next:       NULL,

	enc_blocksize:	 BLOWFISH_BLOCK_SIZE,
	keyminlen:		 BLOWFISH_KEY_MIN_LEN,
	keydeflen:		 BLOWFISH_KEY_MIN_LEN,
	keymaxlen:		 BLOWFISH_KEY_MAX_LEN,
};

#define  SERPENT_KEY_MIN_LEN	128
#define  SERPENT_KEY_DEF_LEN	128
#define  SERPENT_KEY_MAX_LEN	256

static struct encrypt_desc encrypt_desc_serpent =
{
	algo_type: 	    IKE_ALG_ENCRYPT,
	algo_id:   	    OAKLEY_SERPENT_CBC,
	algo_next: 	    NULL,

	enc_blocksize:   SERPENT_BLOCK_SIZE,
	keyminlen:		 SERPENT_KEY_MIN_LEN,
	keydeflen:		 SERPENT_KEY_DEF_LEN,
	keymaxlen:		 SERPENT_KEY_MAX_LEN,
};

#define  TWOFISH_KEY_MIN_LEN	128
#define  TWOFISH_KEY_DEF_LEN	128
#define  TWOFISH_KEY_MAX_LEN	256

static struct encrypt_desc encrypt_desc_twofish =
{
	algo_type: 	     IKE_ALG_ENCRYPT,
	algo_id:   	     OAKLEY_TWOFISH_CBC,
	algo_next: 	     NULL,

	enc_blocksize:	 TWOFISH_BLOCK_SIZE,
	keydeflen:		 TWOFISH_KEY_MIN_LEN,
	keyminlen:		 TWOFISH_KEY_DEF_LEN,
	keymaxlen:		 TWOFISH_KEY_MAX_LEN,
};

static struct encrypt_desc encrypt_desc_twofish_ssh =
{
	algo_type: 	     IKE_ALG_ENCRYPT,
	algo_id:   	     OAKLEY_TWOFISH_CBC_SSH,
	algo_next: 	     NULL,

	enc_blocksize:	 TWOFISH_BLOCK_SIZE,
	keydeflen:		 TWOFISH_KEY_MIN_LEN,
	keyminlen:		 TWOFISH_KEY_DEF_LEN,
	keymaxlen:		 TWOFISH_KEY_MAX_LEN,
};

static struct hash_desc hash_desc_md5 =
{
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_MD5,
	algo_next: NULL,
	hash_digest_size: HASH_SIZE_MD5,
};

static struct hash_desc hash_desc_sha1 =
{
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_SHA,
	algo_next: NULL,
	hash_digest_size: HASH_SIZE_SHA1,
};

static struct hash_desc hash_desc_sha2_256 = {
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_SHA2_256,
	algo_next: NULL,
	hash_digest_size: HASH_SIZE_SHA256,
};

static struct hash_desc hash_desc_sha2_384 = {
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_SHA2_384,
	algo_next: NULL,
	hash_digest_size: HASH_SIZE_SHA384,
};

static struct hash_desc hash_desc_sha2_512 = {
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_SHA2_512,
	algo_next: NULL,
	hash_digest_size: HASH_SIZE_SHA512,
};

const struct dh_desc unset_group = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_NONE,
	algo_next:  NULL,
	ke_size:    0
};

static struct dh_desc dh_desc_modp_768 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_768_BIT,
	algo_next:  NULL,
	ke_size:    768 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_1024 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_1024_BIT,
	algo_next:  NULL,
	ke_size:    1024 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_1536 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_1536_BIT,
	algo_next:  NULL,
	ke_size:    1536 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_2048 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_2048_BIT,
	algo_next:  NULL,
	ke_size:    2048 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_3072 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_3072_BIT,
	algo_next:  NULL,
	ke_size:    3072 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_4096 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_4096_BIT,
	algo_next:  NULL,
	ke_size:    4096 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_6144 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_6144_BIT,
	algo_next:  NULL,
	ke_size:    6144 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_8192 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_8192_BIT,
	algo_next:  NULL,
	ke_size:    8192 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_ecp_256 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    ECP_256_BIT,
	algo_next:  NULL,
	ke_size:    2*256 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_ecp_384 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    ECP_384_BIT,
	algo_next:  NULL,
	ke_size:    2*384 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_ecp_521 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    ECP_521_BIT,
	algo_next:  NULL,
	ke_size:    2*528 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_1024_160 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_1024_160,
	algo_next:  NULL,
	ke_size:    1024 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_2048_224 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_2048_224,
	algo_next:  NULL,
	ke_size:    2048 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_modp_2048_256 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    MODP_2048_256,
	algo_next:  NULL,
	ke_size:    2048 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_ecp_192 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    ECP_192_BIT,
	algo_next:  NULL,
	ke_size:    2*192 / BITS_PER_BYTE
};

static struct dh_desc dh_desc_ecp_224 = {
	algo_type:  IKE_ALG_DH_GROUP,
	algo_id:    ECP_224_BIT,
	algo_next:  NULL,
	ke_size:    2*224 / BITS_PER_BYTE
};

bool init_crypto(void)
{
	enumerator_t *enumerator;
	encryption_algorithm_t encryption_alg;
	hash_algorithm_t hash_alg;
	diffie_hellman_group_t dh_group;
	bool no_md5  = TRUE;
	bool no_sha1 = TRUE;

	enumerator = lib->crypto->create_hasher_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &hash_alg))
	{
		const struct hash_desc *desc;

		switch (hash_alg)
		{
			case HASH_SHA1:
				desc = &hash_desc_sha1;
				no_sha1 = FALSE;
				break;
			case HASH_SHA256:
				desc = &hash_desc_sha2_256;
				break;
			case HASH_SHA384:
				desc = &hash_desc_sha2_384;
				break;
			case HASH_SHA512:
				desc = &hash_desc_sha2_512;
				break;
			case HASH_MD5:
				desc = &hash_desc_md5;
				no_md5 = FALSE;
				break;
			default:
				continue;
		}
		ike_alg_add((struct ike_alg *)desc);
	}
	enumerator->destroy(enumerator);

	if (no_sha1 || no_md5)
	{
		plog("pluto cannot run without a %s%s%s hasher",
			 (no_sha1) ? "SHA-1" : "",
			 (no_sha1 && no_md5) ? " and " : "",
			 (no_md5) ? "MD5" : "");
		return FALSE;
	}

	enumerator = lib->crypto->create_crypter_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &encryption_alg))
	{
		const struct encrypt_desc *desc;

		switch (encryption_alg)
		{
			case ENCR_DES:
				desc = &encrypt_desc_des;
				break;
			case ENCR_3DES:
				desc = &encrypt_desc_3des;
				break;
			case ENCR_BLOWFISH:
				desc = &encrypt_desc_blowfish;
				break;
			case ENCR_AES_CBC:
				desc = &encrypt_desc_aes;
				break;
			case ENCR_CAMELLIA_CBC:
				desc = &encrypt_desc_camellia;
				break;
			case ENCR_TWOFISH_CBC:
				desc = &encrypt_desc_twofish;
				ike_alg_add((struct ike_alg *)&encrypt_desc_twofish_ssh);
				break;
			case ENCR_SERPENT_CBC:
				desc = &encrypt_desc_serpent;
				break;
			default:
				continue;
		}
		ike_alg_add((struct ike_alg *)desc);
	}
	enumerator->destroy(enumerator);

	enumerator = lib->crypto->create_dh_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &dh_group))
	{
		const struct dh_desc *desc;

		switch (dh_group)
		{
			case MODP_768_BIT:
				desc = &dh_desc_modp_768;
				break;
			case MODP_1024_BIT:
				desc = &dh_desc_modp_1024;
				break;
			case MODP_1536_BIT:
				desc = &dh_desc_modp_1536;
				break;
			case MODP_2048_BIT:
				desc = &dh_desc_modp_2048;
				break;
			case MODP_3072_BIT:
				desc = &dh_desc_modp_3072;
				break;
			case MODP_4096_BIT:
				desc = &dh_desc_modp_4096;
				break;
			case MODP_6144_BIT:
				desc = &dh_desc_modp_6144;
				break;
			case MODP_8192_BIT:
				desc = &dh_desc_modp_8192;
				break;
			case ECP_256_BIT:
				desc = &dh_desc_ecp_256;
				break;
			case ECP_384_BIT:
				desc = &dh_desc_ecp_384;
				break;
			case ECP_521_BIT:
				desc = &dh_desc_ecp_521;
				break;
			case MODP_1024_160:
				desc = &dh_desc_modp_1024_160;
				break;
			case MODP_2048_224:
				desc = &dh_desc_modp_2048_224;
				break;
			case MODP_2048_256:
				desc = &dh_desc_modp_2048_256;
				break;
			case ECP_192_BIT:
				desc = &dh_desc_ecp_192;
				break;
			case ECP_224_BIT:
				desc = &dh_desc_ecp_224;
				break;
			default:
				continue;
		}
		ike_alg_add((struct ike_alg *)desc);
	}
	enumerator->destroy(enumerator);
	return TRUE;
}

void free_crypto(void)
{
	/* currently nothing to do */
}

/**
 * Converts IKEv1 encryption algorithm name to crypter name
 */
encryption_algorithm_t oakley_to_encryption_algorithm(int alg)
{
	switch (alg)
	{
		case OAKLEY_DES_CBC:
			return ENCR_DES;
		case OAKLEY_IDEA_CBC:
			return ENCR_IDEA;
		case OAKLEY_BLOWFISH_CBC:
			return ENCR_BLOWFISH;
		case OAKLEY_RC5_R16_B64_CBC:
			return ENCR_RC5;
		case OAKLEY_3DES_CBC:
			return ENCR_3DES;
		case OAKLEY_CAST_CBC:
			return ENCR_CAST;
		case OAKLEY_AES_CBC:
			return ENCR_AES_CBC;
		case OAKLEY_CAMELLIA_CBC:
			return ENCR_CAMELLIA_CBC;
		case OAKLEY_SERPENT_CBC:
			return ENCR_SERPENT_CBC;
		case OAKLEY_TWOFISH_CBC:
		case OAKLEY_TWOFISH_CBC_SSH:
			return ENCR_TWOFISH_CBC;
		default:
			return ENCR_UNDEFINED;
	}
}

/**
 * Converts IKEv1 hash algorithm name to hasher name
 */
hash_algorithm_t oakley_to_hash_algorithm(int alg)
{
	switch (alg)
	{
		case OAKLEY_MD5:
			return HASH_MD5;
		case OAKLEY_SHA:
			return HASH_SHA1;
		case OAKLEY_SHA2_256:
			return HASH_SHA256;
		case OAKLEY_SHA2_384:
			return HASH_SHA384;
		case OAKLEY_SHA2_512:
			return HASH_SHA512;
		default:
			return HASH_UNKNOWN;
	}
}

/**
 * Converts IKEv1 hash algorithm name to IKEv2 prf name
 */
pseudo_random_function_t oakley_to_prf(int alg)
{
	switch (alg)
	{
		case OAKLEY_MD5:
			return PRF_HMAC_MD5;
		case OAKLEY_SHA:
			return PRF_HMAC_SHA1;
		case OAKLEY_SHA2_256:
			return PRF_HMAC_SHA2_256;
		case OAKLEY_SHA2_384:
			return PRF_HMAC_SHA2_384;
		case OAKLEY_SHA2_512:
			return PRF_HMAC_SHA2_512;
		default:
			return PRF_UNDEFINED;
	}
}

/**
 * Maps IKEv1 authentication method to IKEv2 signature scheme
 */
signature_scheme_t oakley_to_signature_scheme(int method)
{
	switch (method)
	{
		case OAKLEY_RSA_SIG:
		case XAUTHInitRSA:
		case XAUTHRespRSA:
			return SIGN_RSA_EMSA_PKCS1_NULL;
		case OAKLEY_ECDSA_256:
		case OAKLEY_ECDSA_384:
		case OAKLEY_ECDSA_521:
			return SIGN_ECDSA_WITH_NULL;
		default:
			return SIGN_UNKNOWN;
	}
}

/**
 * Converts IKEv2 encryption to IKEv1 encryption algorithm
 */
int oakley_from_encryption_algorithm(encryption_algorithm_t alg)
{
	switch (alg)
	{
		case ENCR_DES:
			return OAKLEY_DES_CBC;
		case ENCR_3DES:
			return OAKLEY_3DES_CBC;
		case ENCR_RC5:
			return OAKLEY_RC5_R16_B64_CBC;
		case ENCR_IDEA:
			return OAKLEY_IDEA_CBC;
		case ENCR_CAST:
			return OAKLEY_CAST_CBC;
		case ENCR_BLOWFISH:
			return OAKLEY_BLOWFISH_CBC;
		case ENCR_AES_CBC:
			return OAKLEY_AES_CBC;
		case ENCR_CAMELLIA_CBC:
			return OAKLEY_CAMELLIA_CBC;
		case ENCR_SERPENT_CBC:
			return OAKLEY_SERPENT_CBC;
	case ENCR_TWOFISH_CBC:
			return OAKLEY_TWOFISH_CBC;
		default:
			return 0;
	}
}

/**
 * Converts IKEv2 integrity to IKEv1 hash algorithm
 */
int oakley_from_integrity_algorithm(integrity_algorithm_t alg)
{
	switch (alg)
	{
		case AUTH_HMAC_MD5_96:
			return OAKLEY_MD5;
		case AUTH_HMAC_SHA1_96:
			return OAKLEY_SHA;
		case AUTH_HMAC_SHA2_256_128:
			return OAKLEY_SHA2_256;
		case AUTH_HMAC_SHA2_384_192:
			return OAKLEY_SHA2_384;
		case AUTH_HMAC_SHA2_512_256:
			return OAKLEY_SHA2_512;
		default:
			return 0;
	}
}

/**
 * Converts IKEv2 encryption to IKEv1 ESP encryption algorithm
 */
int esp_from_encryption_algorithm(encryption_algorithm_t alg)
{
	switch (alg)
	{
		case ENCR_DES:
			return ESP_DES;
		case ENCR_3DES:
			return ESP_3DES;
		case ENCR_RC5:
			return ESP_RC5;
		case ENCR_IDEA:
			return ESP_IDEA;
		case ENCR_CAST:
			return ESP_CAST;
		case ENCR_BLOWFISH:
			return ESP_BLOWFISH;
		case ENCR_NULL:
			return ESP_NULL;
		case ENCR_AES_CBC:
			return ESP_AES;
		case ENCR_AES_CTR:
			return ESP_AES_CTR;
		case ENCR_AES_CCM_ICV8:
			return ESP_AES_CCM_8;
		case ENCR_AES_CCM_ICV12:
			return ESP_AES_CCM_12;
		case ENCR_AES_CCM_ICV16:
			return ESP_AES_CCM_16;
		case ENCR_AES_GCM_ICV8:
			return ESP_AES_GCM_8;
		case ENCR_AES_GCM_ICV12:
			return ESP_AES_GCM_12;
		case ENCR_AES_GCM_ICV16:
			return ESP_AES_GCM_16;
		case ENCR_CAMELLIA_CBC:
			return ESP_CAMELLIA;
		case ENCR_NULL_AUTH_AES_GMAC:
			return ESP_AES_GMAC;
		case ENCR_SERPENT_CBC:
			return ESP_SERPENT;
		case ENCR_TWOFISH_CBC:
			return ESP_TWOFISH;
		default:
			return 0;
	}
}

/**
 * Converts IKEv2 integrity to IKEv1 ESP authentication algorithm
 */
int esp_from_integrity_algorithm(integrity_algorithm_t alg)
{
	switch (alg)
	{
		case AUTH_HMAC_MD5_96:
			return AUTH_ALGORITHM_HMAC_MD5;
		case AUTH_HMAC_SHA1_96:
			return AUTH_ALGORITHM_HMAC_SHA1;
		case AUTH_AES_XCBC_96:
			return AUTH_ALGORITHM_AES_XCBC_MAC;
		case AUTH_HMAC_SHA2_256_96:
		case AUTH_HMAC_SHA2_256_128:
			return AUTH_ALGORITHM_HMAC_SHA2_256;
		case AUTH_HMAC_SHA2_384_96:
		case AUTH_HMAC_SHA2_384_192:
			return AUTH_ALGORITHM_HMAC_SHA2_384;
		case AUTH_HMAC_SHA2_512_96:
		case AUTH_HMAC_SHA2_512_256:
			return AUTH_ALGORITHM_HMAC_SHA2_512;
		case AUTH_AES_128_GMAC:
			return AUTH_ALGORITHM_AES_128_GMAC;
		case AUTH_AES_192_GMAC:
			return AUTH_ALGORITHM_AES_192_GMAC;
		case AUTH_AES_256_GMAC:
			return AUTH_ALGORITHM_AES_256_GMAC;
		default:
			return 0;
	}
}
