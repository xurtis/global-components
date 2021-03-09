/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4prof.h>
#include <platsupport/io.h>

/* The following functions are generated for the camkes component
 * internally */

/* Set callback for prev_dump event */
typedef void callback_fn(void *);
int prev_dump_reg_callback(callback_fn *cb, void *arg);

/* Signal next_dump event */
void next_dump_emit(void);

SEL4PROF_NO_INSTRUMENT
static void handle_dump(void *_arg)
{
    /* Dump this component */
    prof_dump();

    /* Dump the next in the chain */
    next_dump_emit();
}

SEL4PROF_NO_INSTRUMENT
int benchutilz_setup_profile_dump(UNUSED ps_io_ops_t *io_ops)
{
    int error = prev_dump_reg_callback(handle_dump, NULL);
    if (error != 0) {
        ZF_LOGE("Failed register profile dump callback");
        return error;
    }
    return 0;
}

/* Inject into _post_init */
typedef int (*camkes_module_init_fn_t)(ps_io_ops_t *io_ops);

#define CAMKES_POST_INIT_MODULE_DEFINE(name, init_func) \
    static_assert(init_func != NULL, "Supplied init_func is NULL!"); \
    USED SECTION("_post_init") camkes_module_init_fn_t name = init_func;

CAMKES_POST_INIT_MODULE_DEFINE(
    benchutilz_setup_profile_dump_,
    benchutilz_setup_profile_dump
);
