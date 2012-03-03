/*
 * Copyright (C) 2008 Tobias Brunner
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


#include "kernel_netlink_plugin.h"

#include "kernel_netlink_ipsec.h"
#include "kernel_netlink_net.h"

#include <daemon.h>

typedef struct private_kernel_netlink_plugin_t private_kernel_netlink_plugin_t;

/**
 * private data of kernel netlink plugin
 */
struct private_kernel_netlink_plugin_t {
	/**
	 * implements plugin interface
	 */
	kernel_netlink_plugin_t public;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_kernel_netlink_plugin_t *this)
{
	charon->kernel_interface->remove_ipsec_interface(charon->kernel_interface, (kernel_ipsec_constructor_t)kernel_netlink_ipsec_create);
	charon->kernel_interface->remove_net_interface(charon->kernel_interface, (kernel_net_constructor_t)kernel_netlink_net_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *kernel_netlink_plugin_create()
{
	private_kernel_netlink_plugin_t *this = malloc_thing(private_kernel_netlink_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	charon->kernel_interface->add_ipsec_interface(charon->kernel_interface, (kernel_ipsec_constructor_t)kernel_netlink_ipsec_create);
	charon->kernel_interface->add_net_interface(charon->kernel_interface, (kernel_net_constructor_t)kernel_netlink_net_create);

	return &this->public.plugin;
}
