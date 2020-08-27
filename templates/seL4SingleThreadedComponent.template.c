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

#include <platsupport/io.h>
#include <platsupport/driver_module.h>
#include <camkes.h>
#include <camkes/io.h>
#include <utils/util.h>
#include <camkes/tls.h>
#include <camkes/irq.h>
#include <sel4bench/sel4bench.h>
/*- from 'global-endpoint.template.c' import allocate_cap_instance, allocate_rpc_cap_instance with context -*/

/* Force the init sections to be created even if no modules are defined. */
static USED SECTION("_env_init") struct {} dummy_env_init_module;
static USED SECTION("_pre_init") struct {} dummy_pre_init_module;
static USED SECTION("_post_init") struct {} dummy_post_init_module;
/* Definitions so that we can find the list of hardware modules that we need to initialise */

extern camkes_module_init_fn_t __start__env_init[];
extern camkes_module_init_fn_t __stop__env_init[];
extern camkes_module_init_fn_t __start__pre_init[];
extern camkes_module_init_fn_t __stop__pre_init[];
extern camkes_module_init_fn_t __start__post_init[];
extern camkes_module_init_fn_t __stop__post_init[];

static ps_io_ops_t io_ops;


void pre_init(void) {
    int err = camkes_io_ops(&io_ops);
    if (err) {
        ZF_LOGE("Failed to initialize io_ops");
    }
    for (camkes_module_init_fn_t * init_fun = __start__env_init; init_fun < __stop__env_init; init_fun++) {
        err = (*init_fun)(&io_ops);
        if (err) {
            ZF_LOGE("Failed to initialize %p", init_fun);
        }

    }
    for (camkes_module_init_fn_t * init_fun = __start__pre_init; init_fun < __stop__pre_init; init_fun++) {
        err = (*init_fun)(&io_ops);
        if (err) {
            ZF_LOGE("Failed to initialize %p", init_fun);
        }

    }
    err = camkes_call_hardware_init_modules(&io_ops);
    if (err) {
        ZF_LOGE("Failed to initialize hardware init modules");
    }
    for (camkes_module_init_fn_t *init_fun = __start__post_init; init_fun < __stop__post_init; init_fun++) {
        err = (*init_fun)(&io_ops);
        if (err) {
            ZF_LOGE("Failed to initialize %p", init_fun);
        }

    }
}


/*- do allocate_cap_instance(me) -*/
/*- set notification = pop('notification') -*/
/*- do allocate_rpc_cap_instance(me) -*/
/*- set endpoint = pop('endpoint') -*/

/*# Allocate reply cap #*/
/*- if options.realtime -*/
        /*- set reply_cap_slot = alloc('reply_cap_slot', seL4_RTReplyObject) -*/
/*- else -*/
        /*# We're going to need a CNode cap in order to save our pending reply
         * caps in the future.
         #*/
        /*- set cnode = alloc_cap('cnode', my_cnode) -*/
        /*- set reply_cap_slot = alloc_cap('reply_cap_slot', None) -*/
/*- endif -*/


struct handlers {
    seL4_Word badge;
    void (*callback_handler)(seL4_Word, void *);
    void * cookie;
    const char* name;
};

static struct handlers *reg_handlers;
static int num_handlers = 0;
int single_threaded_component_register_handler(seL4_Word badge, const char* name, void (*callback_handler)(seL4_Word, void *), void * cookie) {
    reg_handlers = realloc(reg_handlers, (num_handlers+1) * sizeof(*reg_handlers));
    if (!reg_handlers) {
        ZF_LOGF("Failed to allocate handlers");
    }
    reg_handlers[num_handlers] = (struct handlers) {.badge = badge, .callback_handler = callback_handler, .cookie = cookie, .name = name};
    num_handlers++;
    return 0;
}


/*- if configuration[me.name].get("enable_tracing", 0) == 1 -*/
//#define NUM_TRACES /*? configuration[me.name].get("number_tracepoints", 10) ?*/
#define NUM_TRACES 20

#define START_INDEX 0
#define SUM_INDEX 1
#define COUNT_INDEX 2

typedef struct trace_point {
    const char *name;
    uint64_t start;
    uint64_t sum;
    uint64_t num_tripped;
} trace_point_t;

static trace_point_t trace_points[NUM_TRACES];
static trace_point_t extra_trace_points[NUM_TRACES];

#define ENDPOINTS_TRACE 0
#define NOTIFICATIONS_TRACE 1
#define IRQ_HANDLERS_TRACE 2
#define REGISTERED_HANDLERS_START 3

#define TRACE_START(num) do { \
        if (num < NUM_TRACES) { \
            ccnt_t val; \
            SEL4BENCH_READ_CCNT(val); \
            trace_points[num].start = val; \
        } \
} while (0)

#define TRACE_END_COUNT(num, count) do { \
        if (num < NUM_TRACES) { \
            ccnt_t val; \
            SEL4BENCH_READ_CCNT(val); \
            trace_points[num].sum += val - trace_points[num].start; \
            trace_points[num].num_tripped += count; \
        } \
} while (0)

#define TRACE_END(num) TRACE_END_COUNT(num, 1)

#define EXTRA_TRACE_START(num) do { \
        if (num < NUM_TRACES) { \
            ccnt_t val; \
            SEL4BENCH_READ_CCNT(val); \
            extra_trace_points[num].start = val; \
        } \
} while (0)

#define EXTRA_TRACE_END_COUNT(num, count) do { \
        if (num < NUM_TRACES) { \
            ccnt_t val; \
            SEL4BENCH_READ_CCNT(val); \
            extra_trace_points[num].sum += val - extra_trace_points[num].start; \
            extra_trace_points[num].num_tripped += count; \
        } \
} while (0)

static int num_extra_tp = 0;

void trace_start(void *_arg) {
    for (int i = 0; i < NUM_TRACES; i++) {
        trace_points[i].start = 0;
        trace_points[i].sum = 0;
        trace_points[i].num_tripped = 0;
        extra_trace_points[i].start = 0;
        extra_trace_points[i].sum = 0;
        extra_trace_points[i].num_tripped = 0;
    }
    int res = trace_start_reg_callback(trace_start, NULL);
    if (res) {
        ZF_LOGE("Failed to register trace callback");
    }
}

void trace_stop(void *_arg) {
    printf("traces:%s\n", get_instance_name());
    for (int i = 0; i < MIN(NUM_TRACES, num_handlers+REGISTERED_HANDLERS_START); i++) {
        if (i == ENDPOINTS_TRACE) {
            printf("total_endpoint_calls,");
        } else if (i == NOTIFICATIONS_TRACE) {
            printf("total_notifications,");
        } else if (i == IRQ_HANDLERS_TRACE) {
            printf("irq_handlers,");
        } else if(i >= REGISTERED_HANDLERS_START &&
                  reg_handlers[i-REGISTERED_HANDLERS_START].name) {
            printf("%s,", reg_handlers[i-REGISTERED_HANDLERS_START].name);
        }
        printf("%ld\ncycles,%ld\n", trace_points[i].num_tripped, trace_points[i].sum);
    }
    for (int i = 0; i < num_extra_tp; i++) {
        if (extra_trace_points[i].name != NULL) {
            printf("%s,", extra_trace_points[i].name);
        } else {
            printf("extra_trace_point_%d,", i);
        }
        printf("%ld\ncycles,%ld\n", extra_trace_points[i].num_tripped, extra_trace_points[i].sum);
    }
    int res = trace_stop_reg_callback(trace_stop, NULL);
    if (res) {
        ZF_LOGE("Failed to register trace callback");
    }

}

int trace_extra_point_register_name(int tp_id, const char *name)
{
    if (name == NULL) {
        ZF_LOGE("Invalid name provided to trace_extra_point_register");
        return -1;
    }

    if (tp_id < 0 || tp_id >= NUM_TRACES) {
        ZF_LOGE("Invalid tp ID");
        return -1;
    }

    if (num_extra_tp >= NUM_TRACES) {
        ZF_LOGE("Can't register any more extra trace points");
        return -1;
    }

    if (trace_points[tp_id].name != NULL) {
        ZF_LOGE("Overwriting an existing trace point");
        return -1;
    }

    extra_trace_points[tp_id].name = name;
    num_extra_tp++;

    return 0;
}

void trace_extra_point_wipe_all(void)
{
    for (int i = 0; i < num_extra_tp; i++) {
        extra_trace_points[i].name = NULL;
        extra_trace_points[i].start = 0;
        extra_trace_points[i].sum = 0;
        extra_trace_points[i].num_tripped = 0;
    }
    num_extra_tp = 0;
}

void trace_extra_point_start(int tp_id)
{
    if (likely(tp_id < NUM_TRACES)) {
        EXTRA_TRACE_START(tp_id);
    }
}

void trace_extra_point_end(int tp_id, int count)
{
    if (likely(tp_id < NUM_TRACES)) {
        EXTRA_TRACE_END_COUNT(tp_id, count);
    }
}

/*- else -*/
#define TRACE_START(num)
#define TRACE_END(num)
#define TRACE_END_COUNT(num, count)
void trace_start(void *_arg) {}
void trace_stop(void *_arg) {}

int trace_extra_point_register_name(int tp_pid, const char *name) { return 0; }
void trace_extra_point_wipe_all(void) {}
void trace_extra_point_start(int tp_id) {}
void trace_extra_point_end(int tp_id, int count) {}
/*- endif -*/


seL4_CPtr signal_to_send = 0;

int run(void) {
    int res = trace_start_reg_callback ? trace_start_reg_callback(trace_start, NULL): 0;
    if (res) {
        ZF_LOGE("Failed to register trace callback");
    }
    res = trace_stop_reg_callback ? trace_stop_reg_callback(trace_stop, NULL): 0;
    if (res) {
        ZF_LOGE("Failed to register trace callback");
    }

    /* Now poll for events and handle them */
    seL4_Word badge;
    seL4_Word notification_base = /*? configuration[me.name].get("global_endpoint_base", 1) ?*/;
    seL4_Word endpoint_base = /*? configuration[me.name].get("global_rpc_endpoint_base", 0) ?*/;
    if (notification_base == endpoint_base) {
        ZF_LOGE("Notification and Endpoint badge values share the same base bitfield.\n"
                "This means that they cannot be distinguished from each other.\n"
                "This may result in instability.");
    }
    seL4_TCB_BindNotification(camkes_get_tls()->tcb_cap, /*? notification ?*/);
    /*- if not options.realtime -*/
        camkes_get_tls()->cnode_cap = /*? cnode ?*/;
    /*- endif -*/
        seL4_MessageInfo_t info = /*? generate_seL4_Recv(options, endpoint,
                                                                '&badge',
                                                                 reply_cap_slot) ?*/;

    while (1) {

        if ((badge & endpoint_base) == endpoint_base) {
            int result = 0;
            TRACE_START(ENDPOINTS_TRACE);
            switch (badge) {
#define X(b) \
    case (b):
     /*- for conn in composition.connections -*/
       /*- if conn.type.get_attribute("to_global_rpc_endpoint") and conn.type.get_attribute("to_global_rpc_endpoint").default and conn.to_ends[0].instance == me -*/

        /*? conn.to_end.interface.name ?*/_BADGES_MACRO_X_ITERATOR()
        /*- if not options.realtime -*/
            /*# We need to save the reply cap because the user's implementation may
             * perform operations that overwrite or discard it.
             #*/
            camkes_declare_reply_cap(/*? reply_cap_slot ?*/);
        /*- endif -*/

        result = /*? conn.to_end.interface.name ?*/_handle_message(&info, badge);
        break;
      /*- endif -*/
    /*- endfor -*/
#undef X
               default:
                    // Fall through below
                    result = -1;
            }

            if (result == 1) {
                TRACE_END(ENDPOINTS_TRACE);
                /* Send the response */
                /*-- if not options.realtime -*/
                    camkes_tls_t * tls = camkes_get_tls();
                    assert(tls != NULL);
                    if (tls->reply_cap_in_tcb) {
                        tls->reply_cap_in_tcb = false;
                        info = /*? generate_seL4_ReplyRecv(options, endpoint,
                                                                'info',
                                                                '&badge',
                                                                reply_cap_slot) ?*/;
                    } else {
                        camkes_unprotect_reply_cap();
                        seL4_Send(/*? reply_cap_slot ?*/, info);
                        info = /*? generate_seL4_Recv(options, endpoint,
                                                            '&badge',
                                                            reply_cap_slot) ?*/;
                    }
                /*-- else -*/
                    info = /*? generate_seL4_ReplyRecv(options, endpoint,
                                                            'info',
                                                            '&badge',
                                                            reply_cap_slot) ?*/;
                /*-- endif -*/
                continue;
            } else if (result == 0) {
                TRACE_END(ENDPOINTS_TRACE);
                /* Don't reply to the caller */
                info = /*? generate_seL4_Recv(options, endpoint,
                                                         '&badge',
                                                         reply_cap_slot) ?*/;
                continue;
            } else {
                TRACE_END(ENDPOINTS_TRACE);
            }

        }
        if ((badge & notification_base) == notification_base) {
            TRACE_START(NOTIFICATIONS_TRACE);
            TRACE_START(IRQ_HANDLERS_TRACE);
            int UNUSED num_handlers_called = camkes_handle_global_endpoint_irq(badge);
            TRACE_END_COUNT(IRQ_HANDLERS_TRACE, num_handlers_called);
            for (int i = 0; i < num_handlers; i++) {
                seL4_Word b = reg_handlers[i].badge;
                if ((badge & b) == b) {
                    TRACE_START(i + REGISTERED_HANDLERS_START);
                    reg_handlers[i].callback_handler(b, reg_handlers[i].cookie);
                    TRACE_END(i + REGISTERED_HANDLERS_START);
                }
            }
            TRACE_END(NOTIFICATIONS_TRACE);
        }
        if (signal_to_send) {
            /*? generate_seL4_SignalRecv(options, 'info', 'signal_to_send', 'info', endpoint, '&badge', reply_cap_slot) ?*/;
            signal_to_send = 0;
        } else {
            info = /*? generate_seL4_Recv(options, endpoint,
                                        '&badge',
                                        reply_cap_slot) ?*/;
        }

    }

}
