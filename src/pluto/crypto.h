/* crypto interfaces
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
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

#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <crypto/hashers/hasher.h>
#include <crypto/prfs/prf.h>
#include <credentials/keys/public_key.h>

#include "ike_alg.h"

extern bool init_crypto(void);
extern void free_crypto(void);

extern const struct dh_desc unset_group;      /* magic signifier */

/* unification of cryptographic encoding/decoding algorithms
 * The IV is taken from and returned to st->st_new_iv.
 * This allows the old IV to be retained.
 * Use update_iv to commit to the new IV (for example, once a packet has
 * been validated).
 */

#define MAX_OAKLEY_KEY_LEN0  (3 * DES_CBC_BLOCK_SIZE)
#define MAX_OAKLEY_KEY_LEN  (256/BITS_PER_BYTE)

struct state;   /* forward declaration, dammit */

#define update_iv(st)   memcpy((st)->st_iv, (st)->st_new_iv \
	, (st)->st_iv_len = (st)->st_new_iv_len)

#define set_ph1_iv(st, iv) \
	passert((st)->st_ph1_iv_len <= sizeof((st)->st_ph1_iv)); \
	memcpy((st)->st_ph1_iv, (iv), (st)->st_ph1_iv_len);

/* unification of cryptographic hashing mechanisms */

extern encryption_algorithm_t oakley_to_encryption_algorithm(int alg);
extern hash_algorithm_t oakley_to_hash_algorithm(int alg);
extern pseudo_random_function_t oakley_to_prf(int alg);
extern signature_scheme_t oakley_to_signature_scheme(int method);
extern int oakley_from_encryption_algorithm(encryption_algorithm_t alg);
extern int oakley_from_integrity_algorithm(integrity_algorithm_t alg);
extern int esp_from_encryption_algorithm(encryption_algorithm_t alg);
extern int esp_from_integrity_algorithm(integrity_algorithm_t alg);

