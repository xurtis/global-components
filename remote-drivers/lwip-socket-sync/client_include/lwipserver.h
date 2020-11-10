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

#pragma once

#include <lwip/ip.h>
#include <camkes/dataport.h>

#ifndef ENCODE_DMA_ADDRESS
#define ENCODE_DMA_ADDRESS(buf) ({ \
    dataport_ptr_t wrapped_ptr = dataport_wrap_ptr(buf); \
    ZF_LOGF_IF(wrapped_ptr.id == -1, "Failed to encode DMA address"); \
    uint64_t new_buf = (((uint64_t)wrapped_ptr.id << 32) | ((uint64_t)wrapped_ptr.offset)); \
    new_buf; })
#endif

#ifndef DECODE_DMA_ADDRESS
#define DECODE_DMA_ADDRESS(buf) ({\
        dataport_ptr_t wrapped_ptr = {.id = ((uint64_t)buf >> 32), .offset = (uint64_t)buf & MASK(32)}; \
        void *ptr = dataport_unwrap_ptr(wrapped_ptr); \
        ZF_LOGF_IF(ptr == NULL, "Failed to decode DMA address"); \
        ptr; })
#endif

typedef enum lwipserver_event_type {
    LWIPSERVER_PEER_AVAIL = 1,
    LWIPSERVER_PEER_CLOSED = 2,
    LWIPSERVER_CONNECTED = 4,
    LWIPSERVER_DATA_AVAIL = 8,
} lwipserver_event_type_t;

typedef struct lwipserver_event {
    lwipserver_event_type_t type;
    int socket_fd;
} lwipserver_event_t;

typedef struct tx_msg tx_msg_t;
struct tx_msg {
    int socket_fd;
    size_t total_len;
    size_t done_len;
    ip_addr_t src_addr;
    uint16_t src_port;
    tx_msg_t *next;
    void *cookie_save;
    void *client_cookie;
    void *buf_ref; // Reference to another block of memory for zero-copy
};
static_assert(sizeof(struct tx_msg) <= 128, "struct tx_msg is larger than 128");
