/*
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "parser.h"

#include <library.h>
#include <daemon.h>
#include <utils/linked_list.h>
#include <encoding/payloads/encodings.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/proposal_substructure.h>
#include <encoding/payloads/transform_substructure.h>
#include <encoding/payloads/transform_attribute.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/encryption_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/cert_payload.h>
#include <encoding/payloads/certreq_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/delete_payload.h>
#include <encoding/payloads/vendor_id_payload.h>
#include <encoding/payloads/cp_payload.h>
#include <encoding/payloads/configuration_attribute.h>
#include <encoding/payloads/eap_payload.h>
#include <encoding/payloads/unknown_payload.h>


typedef struct private_parser_t private_parser_t;

/**
 * Private data stored in a context.
 *
 * Contains pointers and counters to store current state.
 */
struct private_parser_t {
	/**
	 * Public members, see parser_t.
	 */
	parser_t public;

	/**
	 * Current bit for reading in input data.
	 */
	u_int8_t bit_pos;

	/**
	 * Current byte for reading in input data.
	 */
	u_int8_t *byte_pos;

	/**
	 * Input data to parse.
	 */
	u_int8_t *input;

	/**
	 * Roof of input, used for length-checking.
	 */
	u_int8_t *input_roof;

	/**
	 * Set of encoding rules for this parsing session.
	 */
	encoding_rule_t *rules;
};

/**
 * Forward declaration
 */
static status_t parse_payload(private_parser_t *this,
							  payload_type_t payload_type, payload_t **payload);

/**
 * Log invalid length error
 */
static bool short_input(private_parser_t *this, int number)
{
	DBG1(DBG_ENC, "  not enough input to parse rule %d %N",
		 number, encoding_type_names, this->rules[number].type);
	return FALSE;
}

/**
 * Log unaligned rules
 */
static bool bad_bitpos(private_parser_t *this, int number)
{
	DBG1(DBG_ENC, "  found rule %d %N on bitpos %d",
		 number, encoding_type_names, this->rules[number].type, this->bit_pos);
	return FALSE;
}

/**
 * Parse a 4-Bit unsigned integer from the current parsing position.
 */
static bool parse_uint4(private_parser_t *this, int rule_number,
						u_int8_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int8_t) > this->input_roof)
	{
		return short_input(this, rule_number);
	}
	switch (this->bit_pos)
	{
		case 0:
			if (output_pos)
			{
				*output_pos = *(this->byte_pos) >> 4;
			}
			this->bit_pos = 4;
			break;
		case 4:
			if (output_pos)
			{
				*output_pos = *(this->byte_pos) & 0x0F;
			}
			this->bit_pos = 0;
			this->byte_pos++;
			break;
		default:
			return bad_bitpos(this, rule_number);
	}
	if (output_pos)
	{
		DBG3(DBG_ENC, "   => %d", *output_pos);
	}
	return TRUE;
}

/**
 * Parse a 8-Bit unsigned integer from the current parsing position.
 */
static bool parse_uint8(private_parser_t *this, int rule_number,
						u_int8_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int8_t) > this->input_roof)
	{
		return short_input(this, rule_number);
	}
	if (this->bit_pos)
	{
		return bad_bitpos(this, rule_number);
	}
	if (output_pos)
	{
		*output_pos = *(this->byte_pos);
		DBG3(DBG_ENC, "   => %d", *output_pos);
	}
	this->byte_pos++;
	return TRUE;
}

/**
 * Parse a 15-Bit unsigned integer from the current parsing position.
 */
static bool parse_uint15(private_parser_t *this, int rule_number,
						 u_int16_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int16_t) > this->input_roof)
	{
		return short_input(this, rule_number);
	}
	if (this->bit_pos != 1)
	{
		return bad_bitpos(this, rule_number);
	}
	if (output_pos)
	{
		memcpy(output_pos, this->byte_pos, sizeof(u_int16_t));
		*output_pos = ntohs(*output_pos) & ~0x8000;
		DBG3(DBG_ENC, "   => %d", *output_pos);
	}
	this->byte_pos += sizeof(u_int16_t);
	this->bit_pos = 0;
	return TRUE;
}

/**
 * Parse a 16-Bit unsigned integer from the current parsing position.
 */
static bool parse_uint16(private_parser_t *this, int rule_number,
						 u_int16_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int16_t) > this->input_roof)
	{
		return short_input(this, rule_number);
	}
	if (this->bit_pos)
	{
		return bad_bitpos(this, rule_number);
	}
	if (output_pos)
	{
		memcpy(output_pos, this->byte_pos, sizeof(u_int16_t));
		*output_pos = ntohs(*output_pos);
		DBG3(DBG_ENC, "   => %d", *output_pos);
	}
	this->byte_pos += sizeof(u_int16_t);
	return TRUE;
}
/**
 * Parse a 32-Bit unsigned integer from the current parsing position.
 */
static bool parse_uint32(private_parser_t *this, int rule_number,
						 u_int32_t *output_pos)
{
	if (this->byte_pos + sizeof(u_int32_t) > this->input_roof)
	{
		return short_input(this, rule_number);
	}
	if (this->bit_pos)
	{
		return bad_bitpos(this, rule_number);
	}
	if (output_pos)
	{
		memcpy(output_pos, this->byte_pos, sizeof(u_int32_t));
		*output_pos = ntohl(*output_pos);
		DBG3(DBG_ENC, "   => %d", *output_pos);
	}
	this->byte_pos += sizeof(u_int32_t);
	return TRUE;
}

/**
 * Parse a given amount of bytes and writes them to a specific location
 */
static bool parse_bytes(private_parser_t *this, int rule_number,
						u_int8_t *output_pos, int bytes)
{
	if (this->byte_pos + bytes > this->input_roof)
	{
		return short_input(this, rule_number);
	}
	if (this->bit_pos)
	{
		return bad_bitpos(this, rule_number);
	}
	if (output_pos)
	{
		memcpy(output_pos, this->byte_pos, bytes);
		DBG3(DBG_ENC, "   => %b", output_pos, bytes);
	}
	this->byte_pos += bytes;
	return TRUE;
}

/**
 * Parse a single Bit from the current parsing position
 */
static bool parse_bit(private_parser_t *this, int rule_number,
					  bool *output_pos)
{
	if (this->byte_pos + sizeof(u_int8_t) > this->input_roof)
	{
		return short_input(this, rule_number);
	}
	if (output_pos)
	{
		u_int8_t mask;
		mask = 0x01 << (7 - this->bit_pos);
		*output_pos = *this->byte_pos & mask;

		if (*output_pos)
		{	/* set to a "clean", comparable true */
			*output_pos = TRUE;
		}
		DBG3(DBG_ENC, "   => %d", *output_pos);
	}
	this->bit_pos = (this->bit_pos + 1) % 8;
	if (this->bit_pos == 0)
	{
		this->byte_pos++;
	}
	return TRUE;
}

/**
 * Parse substructures in a list.
 */
static bool parse_list(private_parser_t *this, int rule_number,
			linked_list_t **output_pos, payload_type_t payload_type, int length)
{
	linked_list_t *list = *output_pos;

	if (length < 0)
	{
		return short_input(this, rule_number);
	}
	if (this->bit_pos)
	{
		return bad_bitpos(this, rule_number);
	}
	while (length > 0)
	{
		u_int8_t *pos_before = this->byte_pos;
		payload_t *payload;

		DBG2(DBG_ENC, "  %d bytes left, parsing recursively %N",
			 length, payload_type_names, payload_type);

		if (parse_payload(this, payload_type, &payload) != SUCCESS)
		{
			DBG1(DBG_ENC, "  parsing of a %N substructure failed",
				 payload_type_names, payload_type);
			return FALSE;
		}
		list->insert_last(list, payload);
		length -= this->byte_pos - pos_before;
	}
	if (length != 0)
	{	/* must yield exactly to zero */
		DBG1(DBG_ENC, "  length of %N substructure list invalid",
			 payload_type_names, payload_type);
		return FALSE;
	}
	*output_pos = list;
	return TRUE;
}

/**
 * Parse data from current parsing position in a chunk.
 */
static bool parse_chunk(private_parser_t *this, int rule_number,
						chunk_t *output_pos, int length)
{
	if (this->byte_pos + length > this->input_roof)
	{
		return short_input(this, rule_number);
	}
	if (this->bit_pos)
	{
		return bad_bitpos(this, rule_number);
	}
	if (output_pos)
	{
		*output_pos = chunk_alloc(length);
		memcpy(output_pos->ptr, this->byte_pos, length);
		DBG3(DBG_ENC, "   => %b", output_pos->ptr, length);
	}
	this->byte_pos += length;
	return TRUE;
}

/**
 * Implementation of parser_t.parse_payload.
 */
static status_t parse_payload(private_parser_t *this,
							  payload_type_t payload_type, payload_t **payload)
{
	payload_t *pld;
	void *output;
	size_t rule_count;
	int payload_length = 0, spi_size = 0, attribute_length = 0;
	u_int16_t ts_type = 0;
	bool attribute_format = FALSE;
	int rule_number;
	encoding_rule_t *rule;

	/* create instance of the payload to parse */
	pld = payload_create(payload_type);

	DBG2(DBG_ENC, "parsing %N payload, %d bytes left",
		 payload_type_names, payload_type, this->input_roof - this->byte_pos);

	DBG3(DBG_ENC, "parsing payload from %b",
		 this->byte_pos, this->input_roof - this->byte_pos);

	if (pld->get_type(pld) == UNKNOWN_PAYLOAD)
	{
		DBG1(DBG_ENC, "  payload type %d is unknown, handling as %N",
			 payload_type, payload_type_names, UNKNOWN_PAYLOAD);
	}

	/* base pointer for output, avoids casting in every rule */
	output = pld;

	/* parse the payload with its own rulse */
	pld->get_encoding_rules(pld, &this->rules, &rule_count);
	for (rule_number = 0; rule_number < rule_count; rule_number++)
	{
		rule = &(this->rules[rule_number]);
		DBG2(DBG_ENC, "  parsing rule %d %N",
			 rule_number, encoding_type_names, rule->type);
		switch (rule->type)
		{
			case U_INT_4:
			{
				if (!parse_uint4(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case U_INT_8:
			{
				if (!parse_uint8(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case U_INT_16:
			{
				if (!parse_uint16(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case U_INT_32:
			{
				if (!parse_uint32(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case IKE_SPI:
			{
				if (!parse_bytes(this, rule_number, output + rule->offset, 8))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case RESERVED_BIT:
			{
				if (!parse_bit(this, rule_number, NULL))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case RESERVED_BYTE:
			{
				if (!parse_uint8(this, rule_number, NULL))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case FLAG:
			{
				if (!parse_bit(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case PAYLOAD_LENGTH:
			{
				if (!parse_uint16(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				/* parsed u_int16 should be aligned */
				payload_length = *(u_int16_t*)(output + rule->offset);
				if (payload_length < UNKNOWN_PAYLOAD_HEADER_LENGTH)
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case HEADER_LENGTH:
			{
				if (!parse_uint32(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case SPI_SIZE:
			{
				if (!parse_uint8(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				spi_size = *(u_int8_t*)(output + rule->offset);
				break;
			}
			case SPI:
			{
				if (!parse_chunk(this, rule_number, output + rule->offset,
								 spi_size))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case PROPOSALS:
			{
				if (payload_length < SA_PAYLOAD_HEADER_LENGTH ||
					!parse_list(this, rule_number, output + rule->offset,
								PROPOSAL_SUBSTRUCTURE,
								payload_length - SA_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case TRANSFORMS:
			{
				if (payload_length <
							spi_size + PROPOSAL_SUBSTRUCTURE_HEADER_LENGTH ||
					!parse_list(this, rule_number, output + rule->offset,
							TRANSFORM_SUBSTRUCTURE, payload_length - spi_size -
										PROPOSAL_SUBSTRUCTURE_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case TRANSFORM_ATTRIBUTES:
			{
				if (payload_length < TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH ||
					!parse_list(this, rule_number, output + rule->offset,
						TRANSFORM_ATTRIBUTE,
						payload_length - TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case CONFIGURATION_ATTRIBUTES:
			{
				if (payload_length < CP_PAYLOAD_HEADER_LENGTH ||
					!parse_list(this, rule_number, output + rule->offset,
								CONFIGURATION_ATTRIBUTE,
								payload_length - CP_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case ATTRIBUTE_FORMAT:
			{
				if (!parse_bit(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				attribute_format = *(bool*)(output + rule->offset);
				break;
			}
			case ATTRIBUTE_TYPE:
			{
				if (!parse_uint15(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case CONFIGURATION_ATTRIBUTE_LENGTH:
			{
				if (!parse_uint16(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				attribute_length = *(u_int16_t*)(output + rule->offset);
				break;
			}
			case ATTRIBUTE_LENGTH_OR_VALUE:
			{
				if (!parse_uint16(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				attribute_length = *(u_int16_t*)(output + rule->offset);
				break;
			}
			case ATTRIBUTE_VALUE:
			{
				if (attribute_format == FALSE &&
					!parse_chunk(this, rule_number, output + rule->offset,
								 attribute_length))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case NONCE_DATA:
			{
				if (payload_length < NONCE_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
								 payload_length - NONCE_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case ID_DATA:
			{
				if (payload_length < ID_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
								 payload_length - ID_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case AUTH_DATA:
			{
				if (payload_length < AUTH_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
								 payload_length - AUTH_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case CERT_DATA:
			{
				if (payload_length < CERT_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
								 payload_length - CERT_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case CERTREQ_DATA:
			{
				if (payload_length < CERTREQ_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
								 payload_length - CERTREQ_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case EAP_DATA:
			{
				if (payload_length < EAP_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
								 payload_length - EAP_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case SPIS:
			{
				if (payload_length < DELETE_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
								 payload_length - DELETE_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case VID_DATA:
			{
				if (payload_length < VENDOR_ID_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
							payload_length - VENDOR_ID_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case CONFIGURATION_ATTRIBUTE_VALUE:
			{
				if (!parse_chunk(this, rule_number, output + rule->offset,
								 attribute_length))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case KEY_EXCHANGE_DATA:
			{
				if (payload_length < KE_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
								 payload_length - KE_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case NOTIFICATION_DATA:
			{
				if (payload_length < NOTIFY_PAYLOAD_HEADER_LENGTH + spi_size ||
					!parse_chunk(this, rule_number, output + rule->offset,
						payload_length - NOTIFY_PAYLOAD_HEADER_LENGTH - spi_size))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case ENCRYPTED_DATA:
			{
				if (payload_length < ENCRYPTION_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
							payload_length - ENCRYPTION_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case TS_TYPE:
			{
				if (!parse_uint8(this, rule_number, output + rule->offset))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				ts_type = *(u_int8_t*)(output + rule->offset);
				break;
			}
			case ADDRESS:
			{
				int address_length = (ts_type == TS_IPV4_ADDR_RANGE) ? 4 : 16;

				if (!parse_chunk(this, rule_number, output + rule->offset,
								 address_length))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case TRAFFIC_SELECTORS:
			{
				if (payload_length < TS_PAYLOAD_HEADER_LENGTH ||
					!parse_list(this, rule_number, output + rule->offset,
								TRAFFIC_SELECTOR_SUBSTRUCTURE,
								payload_length - TS_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			case UNKNOWN_DATA:
			{
				if (payload_length < UNKNOWN_PAYLOAD_HEADER_LENGTH ||
					!parse_chunk(this, rule_number, output + rule->offset,
								payload_length - UNKNOWN_PAYLOAD_HEADER_LENGTH))
				{
					pld->destroy(pld);
					return PARSE_ERROR;
				}
				break;
			}
			default:
			{
				DBG1(DBG_ENC, "  no rule to parse rule %d %N",
					 rule_number, encoding_type_names, rule->type);
				pld->destroy(pld);
				return PARSE_ERROR;
			}
		}
		/* process next rulue */
		rule++;
	}

	*payload = pld;
	DBG2(DBG_ENC, "parsing %N payload finished",
		 payload_type_names, payload_type);
	return SUCCESS;
}

/**
 * Implementation of parser_t.get_remaining_byte_count.
 */
static int get_remaining_byte_count (private_parser_t *this)
{
	return this->input_roof - this->byte_pos;
}

/**
 * Implementation of parser_t.reset_context.
 */
static void reset_context (private_parser_t *this)
{
	this->byte_pos = this->input;
	this->bit_pos = 0;
}

/**
 * Implementation of parser_t.destroy.
 */
static void destroy(private_parser_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
parser_t *parser_create(chunk_t data)
{
	private_parser_t *this = malloc_thing(private_parser_t);

	this->public.parse_payload = (status_t(*)(parser_t*,payload_type_t,payload_t**))parse_payload;
	this->public.reset_context = (void(*)(parser_t*)) reset_context;
	this->public.get_remaining_byte_count = (int (*) (parser_t *))get_remaining_byte_count;
	this->public.destroy = (void(*)(parser_t*)) destroy;

	this->input = data.ptr;
	this->byte_pos = data.ptr;
	this->bit_pos = 0;
	this->input_roof = data.ptr + data.len;

	return &this->public;
}

