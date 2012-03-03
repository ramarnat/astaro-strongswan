/*
 * Copyright (C) 2008-2010 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
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

#include "utils.h"

#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <dirent.h>
#include <time.h>

#include "enum.h"
#include "debug.h"

ENUM(status_names, SUCCESS, DESTROY_ME,
	"SUCCESS",
	"FAILED",
	"OUT_OF_RES",
	"ALREADY_DONE",
	"NOT_SUPPORTED",
	"INVALID_ARG",
	"NOT_FOUND",
	"PARSE_ERROR",
	"VERIFY_ERROR",
	"INVALID_STATE",
	"DESTROY_ME",
	"NEED_MORE",
);

/**
 * Described in header.
 */
void *clalloc(void * pointer, size_t size)
{
	void *data;
	data = malloc(size);

	memcpy(data, pointer, size);

	return (data);
}

/**
 * Described in header.
 */
void memxor(u_int8_t dst[], u_int8_t src[], size_t n)
{
	int m, i;

	/* byte wise XOR until dst aligned */
	for (i = 0; (uintptr_t)&dst[i] % sizeof(long) && i < n; i++)
	{
		dst[i] ^= src[i];
	}
	/* try to use words if src shares an aligment with dst */
	switch (((uintptr_t)&src[i] % sizeof(long)))
	{
		case 0:
			for (m = n - sizeof(long); i <= m; i += sizeof(long))
			{
				*(long*)&dst[i] ^= *(long*)&src[i];
			}
			break;
		case sizeof(int):
			for (m = n - sizeof(int); i <= m; i += sizeof(int))
			{
				*(int*)&dst[i] ^= *(int*)&src[i];
			}
			break;
		case sizeof(short):
			for (m = n - sizeof(short); i <= m; i += sizeof(short))
			{
				*(short*)&dst[i] ^= *(short*)&src[i];
			}
			break;
		default:
			break;
	}
	/* byte wise XOR of the rest */
	for (; i < n; i++)
	{
		dst[i] ^= src[i];
	}
}

/**
 * Described in header.
 */
void *memstr(const void *haystack, const char *needle, size_t n)
{
	unsigned const char *pos = haystack;
	size_t l = strlen(needle);
	for (; n >= l; ++pos, --n)
	{
		if (memeq(pos, needle, l))
		{
			return (void*)pos;
		}
	}
	return NULL;
}

/**
 * Described in header.
 */
char* translate(char *str, const char *from, const char *to)
{
	char *pos = str;
	if (strlen(from) != strlen(to))
	{
		return str;
	}
	while (pos && *pos)
	{
		char *match;
		if ((match = strchr(from, *pos)) != NULL)
		{
			*pos = to[match - from];
		}
		pos++;
	}
	return str;
}

/**
 * Described in header.
 */
bool mkdir_p(const char *path, mode_t mode)
{
	int len;
	char *pos, full[PATH_MAX];
	pos = full;
	if (!path || *path == '\0')
	{
		return TRUE;
	}
	len = snprintf(full, sizeof(full)-1, "%s", path);
	if (len < 0 || len >= sizeof(full)-1)
	{
		DBG1(DBG_LIB, "path string %s too long", path);
		return FALSE;
	}
	/* ensure that the path ends with a '/' */
	if (full[len-1] != '/')
	{
		full[len++] = '/';
		full[len] = '\0';
	}
	/* skip '/' at the beginning */
	while (*pos == '/')
	{
		pos++;
	}
	while ((pos = strchr(pos, '/')))
	{
		*pos = '\0';
		if (access(full, F_OK) < 0)
		{
			if (mkdir(full, mode) < 0)
			{
				DBG1(DBG_LIB, "failed to create directory %s", full);
				return FALSE;
			}
		}
		*pos = '/';
		pos++;
	}
	return TRUE;
}

/**
 * Return monotonic time
 */
time_t time_monotonic(timeval_t *tv)
{
#if defined(HAVE_CLOCK_GETTIME) && \
	(defined(HAVE_CONDATTR_CLOCK_MONOTONIC) || \
	 defined(HAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC))
	/* as we use time_monotonic() for condvar operations, we use the
	 * monotonic time source only if it is also supported by pthread. */
	timespec_t ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
	{
		if (tv)
		{
			tv->tv_sec = ts.tv_sec;
			tv->tv_usec = ts.tv_nsec / 1000;
		}
		return ts.tv_sec;
	}
#endif /* HAVE_CLOCK_GETTIME && (...) */
	/* Fallback to non-monotonic timestamps:
	 * On MAC OS X, creating monotonic timestamps is rather difficult. We
	 * could use mach_absolute_time() and catch sleep/wakeup notifications.
	 * We stick to the simpler (non-monotonic) gettimeofday() for now.
	 * But keep in mind: we need the same time source here as in condvar! */
	if (!tv)
	{
		return time(NULL);
	}
	if (gettimeofday(tv, NULL) != 0)
	{	/* should actually never fail if passed pointers are valid */
		return -1;
	}
	return tv->tv_sec;
}

/**
 * return null
 */
void *return_null()
{
	return NULL;
}

/**
 * returns TRUE
 */
bool return_true()
{
	return TRUE;
}

/**
 * returns FALSE
 */
bool return_false()
{
	return FALSE;
}

/**
 * nop operation
 */
void nop()
{
}

#ifndef HAVE_GCC_ATOMIC_OPERATIONS
#include <pthread.h>

/**
 * We use a single mutex for all refcount variables.
 */
static pthread_mutex_t ref_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Increase refcount
 */
void ref_get(refcount_t *ref)
{
	pthread_mutex_lock(&ref_mutex);
	(*ref)++;
	pthread_mutex_unlock(&ref_mutex);
}

/**
 * Decrease refcount
 */
bool ref_put(refcount_t *ref)
{
	bool more_refs;

	pthread_mutex_lock(&ref_mutex);
	more_refs = --(*ref);
	pthread_mutex_unlock(&ref_mutex);
	return !more_refs;
}
#endif /* HAVE_GCC_ATOMIC_OPERATIONS */

/**
 * Described in header.
 */
int time_printf_hook(char *dst, size_t len, printf_hook_spec_t *spec,
					 const void *const *args)
{
	static const char* months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	time_t *time = *((time_t**)(args[0]));
	bool utc = *((bool*)(args[1]));;
	struct tm t;

	if (time == UNDEFINED_TIME)
	{
		return print_in_hook(dst, len, "--- -- --:--:--%s----",
							 utc ? " UTC " : " ");
	}
	if (utc)
	{
		gmtime_r(time, &t);
	}
	else
	{
		localtime_r(time, &t);
	}
	return print_in_hook(dst, len, "%s %02d %02d:%02d:%02d%s%04d",
						 months[t.tm_mon], t.tm_mday, t.tm_hour, t.tm_min,
						 t.tm_sec, utc ? " UTC " : " ", t.tm_year + 1900);
}

/**
 * Described in header.
 */
int time_delta_printf_hook(char *dst, size_t len, printf_hook_spec_t *spec,
						   const void *const *args)
{
	char* unit = "second";
	time_t *arg1 = *((time_t**)(args[0]));
	time_t *arg2 = *((time_t**)(args[1]));
	time_t delta = abs(*arg1 - *arg2);

	if (delta > 2 * 60 * 60 * 24)
	{
		delta /= 60 * 60 * 24;
		unit = "day";
	}
	else if (delta > 2 * 60 * 60)
	{
		delta /= 60 * 60;
		unit = "hour";
	}
	else if (delta > 2 * 60)
	{
		delta /= 60;
		unit = "minute";
	}
	return print_in_hook(dst, len, "%d %s%s", delta, unit, (delta == 1)? "":"s");
}

/**
 * Number of bytes per line to dump raw data
 */
#define BYTES_PER_LINE 16

static char hexdig_upper[] = "0123456789ABCDEF";

/**
 * Described in header.
 */
int mem_printf_hook(char *dst, size_t dstlen,
					printf_hook_spec_t *spec, const void *const *args)
{
	char *bytes = *((void**)(args[0]));
	int len = *((size_t*)(args[1]));

	char buffer[BYTES_PER_LINE * 3];
	char ascii_buffer[BYTES_PER_LINE + 1];
	char *buffer_pos = buffer;
	char *bytes_pos  = bytes;
	char *bytes_roof = bytes + len;
	int line_start = 0;
	int i = 0;
	int written = 0;

	written += print_in_hook(dst, dstlen, "=> %d bytes @ %p", len, bytes);

	while (bytes_pos < bytes_roof)
	{
		*buffer_pos++ = hexdig_upper[(*bytes_pos >> 4) & 0xF];
		*buffer_pos++ = hexdig_upper[ *bytes_pos       & 0xF];

		ascii_buffer[i++] =
				(*bytes_pos > 31 && *bytes_pos < 127) ? *bytes_pos : '.';

		if (++bytes_pos == bytes_roof || i == BYTES_PER_LINE)
		{
			int padding = 3 * (BYTES_PER_LINE - i);

			while (padding--)
			{
				*buffer_pos++ = ' ';
			}
			*buffer_pos++ = '\0';
			ascii_buffer[i] = '\0';

			written += print_in_hook(dst, dstlen, "\n%4d: %s  %s",
									 line_start, buffer, ascii_buffer);

			buffer_pos = buffer;
			line_start += BYTES_PER_LINE;
			i = 0;
		}
		else
		{
			*buffer_pos++ = ' ';
		}
	}
	return written;
}
