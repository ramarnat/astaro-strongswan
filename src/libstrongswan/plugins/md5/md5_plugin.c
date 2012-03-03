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

#include "md5_plugin.h"

#include <library.h>
#include "md5_hasher.h"

typedef struct private_md5_plugin_t private_md5_plugin_t;

/**
 * private data of md5_plugin
 */
struct private_md5_plugin_t {

	/**
	 * public functions
	 */
	md5_plugin_t public;
};

/**
 * Implementation of md5_plugin_t.destroy
 */
static void destroy(private_md5_plugin_t *this)
{
	lib->crypto->remove_hasher(lib->crypto,
							   (hasher_constructor_t)md5_hasher_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *md5_plugin_create()
{
	private_md5_plugin_t *this = malloc_thing(private_md5_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	lib->crypto->add_hasher(lib->crypto, HASH_MD5,
							(hasher_constructor_t)md5_hasher_create);

	return &this->public.plugin;
}

