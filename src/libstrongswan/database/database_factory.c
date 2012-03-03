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

#include "database_factory.h"

#include <utils/linked_list.h>
#include <threading/mutex.h>

typedef struct private_database_factory_t private_database_factory_t;

/**
 * private data of database_factory
 */
struct private_database_factory_t {

	/**
	 * public functions
	 */
	database_factory_t public;

	/**
	 * list of registered database_t implementations
	 */
	linked_list_t *databases;

	/**
	 * mutex to lock access to databases
	 */
	mutex_t *mutex;
};

/**
 * Implementation of database_factory_t.create.
 */
static database_t* create(private_database_factory_t *this, char *uri)
{
	enumerator_t *enumerator;
	database_t *database = NULL;
	database_constructor_t create;

	this->mutex->lock(this->mutex);
	enumerator = this->databases->create_enumerator(this->databases);
	while (enumerator->enumerate(enumerator, &create))
	{
		database = create(uri);
		if (database)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return database;
}

/**
 * Implementation of database_factory_t.add_database.
 */
static void add_database(private_database_factory_t *this,
						 database_constructor_t create)
{
	this->mutex->lock(this->mutex);
	this->databases->insert_last(this->databases, create);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of database_factory_t.remove_database.
 */
static void remove_database(private_database_factory_t *this,
							database_constructor_t create)
{
	this->mutex->lock(this->mutex);
	this->databases->remove(this->databases, create, NULL);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of database_factory_t.destroy
 */
static void destroy(private_database_factory_t *this)
{
	this->databases->destroy(this->databases);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
database_factory_t *database_factory_create()
{
	private_database_factory_t *this = malloc_thing(private_database_factory_t);

	this->public.create = (database_t*(*)(database_factory_t*, char *url))create;
	this->public.add_database = (void(*)(database_factory_t*, database_constructor_t))add_database;
	this->public.remove_database = (void(*)(database_factory_t*, database_constructor_t))remove_database;
	this->public.destroy = (void(*)(database_factory_t*))destroy;

	this->databases = linked_list_create();
	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);

	return &this->public;
}

