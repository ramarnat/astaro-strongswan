/*
 * Copyright (C) 2006 Martin Willi
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

/**
 * @defgroup file_logger file_logger
 * @{ @ingroup listeners
 */

#ifndef FILE_LOGGER_H_
#define FILE_LOGGER_H_

#include <bus/listeners/listener.h>

typedef struct file_logger_t file_logger_t;

/**
 * Logger to files which implements listener_t.
 */
struct file_logger_t {

	/**
	 * Implements the listener_t interface.
	 */
	listener_t listener;

	/**
	 * Set the loglevel for a debug group.
	 *
	 * @param group		debug group to set
	 * @param level		max level to log (0..4)
	 */
	void (*set_level) (file_logger_t *this, debug_t group, level_t level);

	/**
	 * Destroys a file_logger_t object.
	 */
	void (*destroy) (file_logger_t *this);
};

/**
 * Constructor to create a file_logger_t object.
 *
 * @param out		FILE to write to
 * @return			file_logger_t object
 */
file_logger_t *file_logger_create(FILE *out);

#endif /** FILE_LOGGER_H_ @}*/
