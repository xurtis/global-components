/*
 * Copyright 2020, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#include <lwip-socket-sync.h>
#include <camkes.h>
#include <camkes/io.h>

/*- set connection_name = configuration[me.parent.name].get('connection_name') -*/


int lwip_socket_sync_server_init(ps_io_ops_t *io_ops, register_callback_handler_fn_t callback_handler);
int lwip_socket_sync_server_init_late(ps_io_ops_t *io_ops, register_callback_handler_fn_t callback_handler);
unsigned int /*? connection_name ?*/_recv_num_badges(void);

static int init_server_pre(ps_io_ops_t *io_ops) {
    return lwip_socket_sync_server_init(io_ops, single_threaded_component_register_handler);
}

CAMKES_PRE_INIT_MODULE_DEFINE(/*? connection_name ?*/_server_setup_pre, init_server_pre)

static int init_server_post(ps_io_ops_t *io_ops)
{
    return lwip_socket_sync_server_init_late(io_ops,
                                             single_threaded_component_register_handler);
}

CAMKES_POST_INIT_MODULE_DEFINE(/*? connection_name ?*/_server_setup_post, init_server_post)
