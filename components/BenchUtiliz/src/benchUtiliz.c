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

#include <limits.h>
#include <autoconf.h>
#include <camkes.h>
#include <stdio.h>
#include <sel4bench/sel4bench.h>
#include <camkes/tls.h>
#include <sel4/benchmark_utilisation_types.h>
#include <camkes/dataport_caps.h>
#include <string.h>
#include <sel4/log.h>

#define MAGIC_CYCLES 150
/* We're interested in the generic events as well as:
 * - HASWELL_RESOURCE_STALLS_ANY
 * - HASWELL_RESOURCE_STALLS_RS
 * - HASWELL_RESOURCE_STALLS_SB
 * - HASWELL_RESOURCE_STALLS_ROB */

char *counter_names[] = {
    /*
    "L1 i-cache misses",
    "L1 d-cache misses",
    "L1 i-tlb misses",
    "L1 d-tlb misses",
    "Instructions",
    "Branch mispredictions",
    "Memory accesses",
     */
    "Resource stalls any",
    "Resource stalls reservation station",
    "Resource stalls store buffer",
    "Resource stalls ROB",
};

event_id_t benchmarking_events[] = {
    /*
    SEL4BENCH_EVENT_CACHE_L1I_MISS,
    SEL4BENCH_EVENT_CACHE_L1D_MISS,
    SEL4BENCH_EVENT_TLB_L1I_MISS,
    SEL4BENCH_EVENT_TLB_L1D_MISS,
    SEL4BENCH_EVENT_EXECUTE_INSTRUCTION,
    SEL4BENCH_EVENT_BRANCH_MISPREDICT,
    SEL4BENCH_EVENT_MEMORY_ACCESS,
    */
    SEL4BENCH_IA32_HASWELL_EVENT_RESOURCE_STALLS_ANY,
    SEL4BENCH_IA32_HASWELL_EVENT_RESOURCE_STALLS_RS,
    SEL4BENCH_IA32_HASWELL_EVENT_RESOURCE_STALLS_SB,
    SEL4BENCH_IA32_HASWELL_EVENT_RESOURCE_STALLS_ROB,
};

struct {
    uint32_t head;
    uint32_t tail;
    char buf[0x1000];
} extern WEAK volatile *serial_getchar_buf;
WEAK seL4_CPtr serial_getchar_notification(void);
volatile bool flag = 0;

uint64_t ccount = 0;
uint64_t prev, start, ts, overflows;
uint64_t idle_ccount_start;
uint64_t idle_overflow_start;

ccnt_t counter_values[8];
counter_bitfield_t benchmark_bf;

void getchar_handler(void)
{
    seL4_Word badge;
    uint64_t total, kernel, idle;
    while (1) {
        seL4_Wait(serial_getchar_notification(), &badge);
        char ch = serial_getchar_buf->buf[serial_getchar_buf->head];
        serial_getchar_buf->head = (serial_getchar_buf->head + 1) % sizeof(serial_getchar_buf->buf);
        switch (ch) {
        case 'a':
            idle_start();
            break;
        case 'b':
            idle_stop(&total, &kernel, &idle);
            printf("{\n");
            printf("\"total\": %"PRIu64",\n", total);
            printf("\"kernel\": %"PRIu64",\n", kernel);
            printf("\"idle\": %"PRIu64"\n", idle);
            printf("}\n", idle);
            break;
        default:
            break;
        }
    }
}


void idle_start(void)
{
    if (!flag) {
        flag = 1;
        printf("Measurment starting...\n");
        /*
        sel4bench_reset_counters();
        sel4bench_start_counters(benchmark_bf);
        */
        trace_start_emit();
#ifdef CONFIG_BENCHMARK_TRACK_UTILISATION
        seL4_BenchmarkResetAllThreadsUtilisation();
        seL4_BenchmarkResetLog();
#endif
        start = (uint64_t)sel4bench_get_cycle_count();
        idle_ccount_start = ccount;
        idle_overflow_start = overflows;
    }
}

static void print_pcs(seL4_Word num_entries)
{
    seL4_LogBuffer log_buffer = seL4_LogBuffer_new(bench_buffer);
    printf("idle entries = %lu\n", log_buffer.buffer[0]);
    /* Skip the first entry */
    log_buffer.index = 2;
    seL4_LogBuffer_setSize(&log_buffer, num_entries);
    seL4_LogEvent *curr_event = seL4_LogBuffer_next(&log_buffer);
    for (; curr_event != seL4_Null; curr_event = seL4_LogBuffer_next(&log_buffer)) {
        seL4_Log_Type(Sample) *sample = seL4_Log_Cast(Sample) curr_event;
        printf(",%lu,%lx", sample->header.data, sample->pc);
    }
    printf("\n");
}

void idle_stop(uint64_t *total_ret, uint64_t *kernel_ret, uint64_t *idle_ret)
{
    seL4_Word num_entries = 0;
    flag = 0;
    uint64_t total = ((uint64_t)sel4bench_get_cycle_count()) - start;
    if ((overflows - idle_overflow_start) > 0) {
        ZF_LOGE("Cycle counter overflowed during measurement. Stats may not be accurate");
    }
    total += ULONG_MAX * (overflows - idle_overflow_start);
    uint64_t idle_total = ccount - idle_ccount_start;
    //sel4bench_read_and_stop_counters(benchmark_bf, 0, 8, counter_values);
#ifdef CONFIG_BENCHMARK_TRACK_UTILISATION
    num_entries = seL4_BenchmarkFinalizeLog();
    ZF_LOGE("num_entries = %lu", num_entries);
    print_pcs(num_entries);

    seL4_BenchmarkGetThreadUtilisation(camkes_get_tls()->tcb_cap);
    uint64_t *buffer = (uint64_t *)&seL4_GetIPCBuffer()->msg[0];
    seL4_BenchmarkDumpAllThreadsUtilisation();
    *kernel_ret = buffer[BENCHMARK_TOTAL_KERNEL_UTILISATION];
#else
    *kernel_ret = 0;
#endif
    *total_ret = total;
    *idle_ret = idle_total;
    trace_stop_emit();
    /* Dump the counters */
    /*
    printf("{\n");
    for (int i = 0; i < ARRAY_SIZE(benchmarking_events); i++) {
        printf("    %s:%lu\n", counter_names[i], counter_values[i]);
    }
    printf("}\n");
    */
    memset(counter_values, 0, 8);
}


void count_idle(UNUSED void *arg)
{
    prev = sel4bench_get_cycle_count();
    ccount = 0;
    overflows = 0;

    while (1) {
        ts = (uint64_t)sel4bench_get_cycle_count();
        uint64_t diff;

        /* Handle overflow: This thread needs to run at least 2 times
           within any ULONG_MAX cycles period to detect overflows.
           This also assumes that the cycle counter overflows every ULONG_MAX
           cycles which may not be true for all platforms.*/
        if (ts < prev) {
            diff = ULONG_MAX - prev + ts + 1;
            overflows++;
        } else {
            diff = ts - prev;
        }

        if (diff < MAGIC_CYCLES) {
            COMPILER_MEMORY_FENCE();
            ccount += diff;
            COMPILER_MEMORY_FENCE();
        }
        prev = ts;
    }
}

extern dataport_caps_handle_t bench_buffer_handle;

void pre_init(void)
{
    sel4bench_init();
    /*
    seL4_Word n_counters = sel4bench_get_num_counters();
    int n_chunks = sel4bench_get_num_counter_chunks(n_counters, ARRAY_SIZE(benchmarking_events));
    benchmark_bf = sel4bench_enable_counters(ARRAY_SIZE(benchmarking_events),
                                             benchmarking_events, 0, n_counters);
    */
    seL4_CPtr log_cap = dataport_get_nth_frame_cap(&bench_buffer_handle, 0);
    seL4_Error sel4_err = seL4_BenchmarkSetLogBuffer(log_cap);
    ZF_LOGF_IF(sel4_err != seL4_NoError, "Failed to set log buffer");

    int err = bench_to_reg_callback(&count_idle, NULL);
    if (err) {
        ZF_LOGE("Failed to register callback handler");
    }
    bench_from_emit();

    if (serial_putchar_putchar) {
        set_putchar(serial_putchar_putchar);
    }
}

int run(void)
{
    if (&serial_getchar_buf) {
        getchar_handler();
    }

    return 0;
}
