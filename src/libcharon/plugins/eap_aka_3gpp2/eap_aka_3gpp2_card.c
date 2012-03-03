/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "eap_aka_3gpp2_card.h"

#include <daemon.h>

typedef struct private_eap_aka_3gpp2_card_t private_eap_aka_3gpp2_card_t;

/**
 * Private data of an eap_aka_3gpp2_card_t object.
 */
struct private_eap_aka_3gpp2_card_t {

	/**
	 * Public eap_aka_3gpp2_card_t interface.
	 */
	eap_aka_3gpp2_card_t public;

	/**
	 * AKA functions
	 */
	eap_aka_3gpp2_functions_t *f;

	/**
	 * do sequence number checking?
	 */
	bool seq_check;

	/**
	 * SQN stored in this pseudo-USIM
	 */
	char sqn[AKA_SQN_LEN];
};

/**
 * Functions from eap_aka_3gpp2_provider.c
 */
bool eap_aka_3gpp2_get_k(identification_t *id, char k[AKA_K_LEN]);
void eap_aka_3gpp2_get_sqn(char sqn[AKA_SQN_LEN], int offset);

/**
 * Implementation of sim_card_t.get_quintuplet
 */
static status_t get_quintuplet(private_eap_aka_3gpp2_card_t *this,
							   identification_t *id, char rand[AKA_RAND_LEN],
							   char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
							   char ik[AKA_IK_LEN], char res[AKA_RES_MAX],
							   int *res_len)
{
	char *amf, *mac;
	char k[AKA_K_LEN], ak[AKA_AK_LEN], sqn[AKA_SQN_LEN], xmac[AKA_MAC_LEN];

	if (!eap_aka_3gpp2_get_k(id, k))
	{
		DBG1(DBG_IKE, "no EAP key found for %Y to authenticate with AKA", id);
		return FAILED;
	}

	/* AUTN = SQN xor AK | AMF | MAC */
	DBG3(DBG_IKE, "received autn %b", autn, AKA_AUTN_LEN);
	DBG3(DBG_IKE, "using K %b", k, AKA_K_LEN);
	DBG3(DBG_IKE, "using rand %b", rand, AKA_RAND_LEN);
	memcpy(sqn, autn, AKA_SQN_LEN);
	amf = autn + AKA_SQN_LEN;
	mac = autn + AKA_SQN_LEN + AKA_AMF_LEN;

	/* XOR anonymity key AK into SQN to decrypt it */
	this->f->f5(this->f, k, rand, ak);
	DBG3(DBG_IKE, "using ak %b", ak, AKA_AK_LEN);
	memxor(sqn, ak, AKA_SQN_LEN);
	DBG3(DBG_IKE, "using sqn %b", sqn, AKA_SQN_LEN);

	/* calculate expected MAC and compare against received one */
	this->f->f1(this->f, k, rand, sqn, amf, xmac);
	if (!memeq(mac, xmac, AKA_MAC_LEN))
	{
		DBG1(DBG_IKE, "received MAC does not match XMAC");
		DBG3(DBG_IKE, "MAC %b\nXMAC %b", mac, AKA_MAC_LEN, xmac, AKA_MAC_LEN);
		return FAILED;
	}

	if (this->seq_check && memcmp(this->sqn, sqn, AKA_SQN_LEN) >= 0)
	{
		DBG3(DBG_IKE, "received SQN %b\ncurrent SQN %b",
			 sqn, AKA_SQN_LEN, this->sqn, AKA_SQN_LEN);
		return INVALID_STATE;
	}

	/* update stored SQN to the received one */
	memcpy(this->sqn, sqn, AKA_SQN_LEN);

	/* CK/IK */
	this->f->f3(this->f, k, rand, ck);
	this->f->f4(this->f, k, rand, ik);
	/* calculate RES */
	this->f->f2(this->f, k, rand, res);
	*res_len = AKA_RES_MAX;

	return SUCCESS;
}

/**
 * Implementation of sim_card_t.resync
 */
static bool resync(private_eap_aka_3gpp2_card_t *this, identification_t *id,
				   char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	char amf[AKA_AMF_LEN], k[AKA_K_LEN], aks[AKA_AK_LEN], macs[AKA_MAC_LEN];

	if (!eap_aka_3gpp2_get_k(id, k))
	{
		DBG1(DBG_IKE, "no EAP key found for %Y to resync AKA", id);
		return FALSE;
	}

	/* AMF is set to zero in resync */
	memset(amf, 0, AKA_AMF_LEN);
	this->f->f5star(this->f, k, rand, aks);
	this->f->f1star(this->f, k, rand, this->sqn, amf, macs);
	/* AUTS = SQN xor AKS | MACS */
	memcpy(auts, this->sqn, AKA_SQN_LEN);
	memxor(auts, aks, AKA_AK_LEN);
	memcpy(auts + AKA_AK_LEN, macs, AKA_MAC_LEN);

	return TRUE;
}

/**
 * Implementation of eap_aka_3gpp2_card_t.destroy.
 */
static void destroy(private_eap_aka_3gpp2_card_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_aka_3gpp2_card_t *eap_aka_3gpp2_card_create(eap_aka_3gpp2_functions_t *f)
{
	private_eap_aka_3gpp2_card_t *this = malloc_thing(private_eap_aka_3gpp2_card_t);

	this->public.card.get_triplet = (bool(*)(sim_card_t*, identification_t *id, char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN]))return_false;
	this->public.card.get_quintuplet = (status_t(*)(sim_card_t*, identification_t *id, char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN], char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len))get_quintuplet;
	this->public.card.resync = (bool(*)(sim_card_t*, identification_t *id, char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN]))resync;
	this->public.card.get_pseudonym = (identification_t*(*)(sim_card_t*, identification_t *id))return_null;
	this->public.card.set_pseudonym = (void(*)(sim_card_t*, identification_t *id, identification_t *pseudonym))nop;
	this->public.card.get_reauth = (identification_t*(*)(sim_card_t*, identification_t *id, char mk[HASH_SIZE_SHA1], u_int16_t *counter))return_null;
	this->public.card.set_reauth = (void(*)(sim_card_t*, identification_t *id, identification_t* next, char mk[HASH_SIZE_SHA1], u_int16_t counter))nop;
	this->public.destroy = (void(*)(eap_aka_3gpp2_card_t*))destroy;

	this->f = f;
	this->seq_check = lib->settings->get_bool(lib->settings,
									"charon.plugins.eap-aka-3gpp2.seq_check",
#ifdef SEQ_CHECK /* handle legacy compile time configuration as default */
									TRUE);
#else /* !SEQ_CHECK */
									FALSE);
#endif /* SEQ_CHECK */

	eap_aka_3gpp2_get_sqn(this->sqn, 0);

	return &this->public;
}

