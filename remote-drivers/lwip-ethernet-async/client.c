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

#include <autoconf.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sel4/sel4.h>

#include <virtqueue.h>
#include <camkes/virtqueue.h>
#include <camkes/dataport.h>

#include <lwip-ethernet-async.h>

#include <lwip/init.h>
#include <netif/etharp.h>
#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include <lwip/stats.h>
#include <lwip/snmp.h>
#include <lwip/sys.h>

#define NUM_BUFFERS 512
#define BUFFER_SIZE 2048

// TODO Add functionality to query for Ethernet device's link speed
#define LINK_SPEED 1000000000 // Gigabit
#define ETHER_MTU 1500

typedef enum {
    ORIGIN_RX_QUEUE,
    ORIGIN_TX_QUEUE,
} ethernet_buffer_origin_t;

/*
 * These structures track the buffers used to construct packets
 * sent via this network interface.
 *
 * As the interface is asynchronous, when a buffer is freed it isn't
 * returned to the pool until any outstanding asynchronous use
 * completes.
 */
typedef struct ethernet_buffer {
    /* The acutal underlying memory of the buffer */
    unsigned char *buffer;
    /* The encoded DMA address */
    uintptr_t dma_addr;
    /* The physical size of the buffer */
    size_t size;
    /* Whether the buffer has been allocated */
    bool allocated;
    /* Whether the buffer is in use by the ethernet device */
    bool in_async_use;
    /* Queue from which the buffer was allocated */
    char origin;
} ethernet_buffer_t;

typedef struct state {
    struct netif netif;

    /* mac address for this client */
    uint8_t mac[6];
    virtqueue_driver_t tx_virtqueue;
    virtqueue_driver_t rx_virtqueue;
    ps_io_ops_t *io_ops;

    /*
     * Metadata associated with buffers
     */
    ethernet_buffer_t buffer_metadata[NUM_BUFFERS * 2];
    /*
     * Associated data for each element of the TX & RX virtqueue
     */
    ethernet_buffer_t **tx_queue_data;
    ethernet_buffer_t **rx_queue_data;
    /*
     * Free buffers for TX
     */
    ethernet_buffer_t *available_tx[NUM_BUFFERS];
    size_t num_available_tx;
} state_t;

static inline ethernet_buffer_t *alloc_buffer(state_t *state, size_t length)
{
    if (state->num_available_tx > 0) {
        state->num_available_tx -= 1;
        ethernet_buffer_t *buffer =  state->available_tx[state->num_available_tx];

        if (buffer->size < length) {
            /* Requested size too large */
            state->num_available_tx += 1;
            return NULL;
        } else {
            buffer->allocated = true;
            return buffer;
        }
    } else {
        return NULL;
    }
}

static inline void return_buffer(state_t *state, ethernet_buffer_t *buffer)
{
    switch (buffer->origin) {
    case ORIGIN_TX_QUEUE:
        assert(state->num_available_tx < NUM_BUFFERS);
        state->available_tx[state->num_available_tx] = buffer;
        state->num_available_tx += 1;
        break;

    case ORIGIN_RX_QUEUE: {
        virtqueue_ring_object_t new_ring;
        virtqueue_init_ring_object(&new_ring);
        int err = virtqueue_add_available_buf(
            &state->rx_virtqueue,
            &new_ring,
            (void *)buffer->dma_addr,
            buffer->size,
            VQ_RW
        );
        ZF_LOGF_IF(err == 0, "Error while enqueuing available RX buffer, queue full");
        state->rx_queue_data[new_ring.cur] = buffer;
        break;
    }
    }
}

static inline void free_buffer(state_t *state, ethernet_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->allocated);

    buffer->allocated = false;

    if (!buffer->in_async_use) {
        return_buffer(state, buffer);
    }
}

static inline void mark_buffer_used(ethernet_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->allocated);
    assert(!buffer->in_async_use);

    buffer->in_async_use = true;
}

static inline void mark_buffer_unused(state_t *state, ethernet_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->in_async_use);

    buffer->in_async_use = false;

    if (!buffer->allocated) {
        return_buffer(state, buffer);
    }
}

typedef struct lwip_custom_pbuf {
    struct pbuf_custom custom;
    ethernet_buffer_t *buffer;
    state_t *state;
} lwip_custom_pbuf_t;
LWIP_MEMPOOL_DECLARE(
    RX_POOL,
    NUM_BUFFERS * 2,
    sizeof(lwip_custom_pbuf_t),
    "Zero-copy RX pool"
);

static void interface_free_buffer(struct pbuf *buf)
{
    SYS_ARCH_DECL_PROTECT(old_level);

    lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) buf;

    SYS_ARCH_PROTECT(old_level);
    free_buffer(custom_pbuf->state, custom_pbuf->buffer);
    LWIP_MEMPOOL_FREE(RX_POOL, custom_pbuf);
    SYS_ARCH_UNPROTECT(old_level);
}

static struct pbuf *create_interface_buffer(
    state_t *state,
    ethernet_buffer_t *buffer,
    size_t length
) {
    lwip_custom_pbuf_t *custom_pbuf =
        (lwip_custom_pbuf_t *) LWIP_MEMPOOL_ALLOC(RX_POOL);

    custom_pbuf->state = state;
    custom_pbuf->buffer = buffer;
    custom_pbuf->custom.custom_free_function = interface_free_buffer;

    return pbuf_alloced_custom(
        PBUF_RAW,
        length,
        PBUF_REF,
        &custom_pbuf->custom,
        buffer->buffer,
        buffer->size
    );
}



#if 0
struct id_state_mapper {
    uint32_t dataport_id;
    state_t *state;
};

static struct id_state_mapper *mapper;
static size_t mapper_len;

typedef enum {
    ORIGIN_RX_QUEUE,
    ORIGIN_TX_QUEUE,
} origin_queue;

/* 1500 is the standard ethernet MTU at the network layer. */
#define ETHER_MTU 1500

unsigned in_queue;

static void lwip_recycle_tx_bufs(state_t *state, bool once)
{
    virtqueue_ring_object_t handle;
    virtqueue_init_ring_object(&handle);
    unsigned len = 0;
    uint64_t buf;

    int more = virtqueue_get_used_buf(&state->tx_virtqueue, &handle, &len);
    while (more) {
        vq_flags_t flag;
        while (1) {
            more = virtqueue_gather_used(&state->tx_virtqueue, &handle,
                                         &buf, &len, &flag);
            if (more == 0) {
                break;
            }
            // assert(DECODE_DMA_ADDRESS(buf) == NULL);
            ZF_LOGF_IF(DECODE_DMA_ADDRESS(buf) == NULL, "decoded DMA buffer is NULL");

            uintptr_t decoded_buf = DECODE_DMA_ADDRESS(buf);
            /* HACK: lwIP bumps the RX payload to be the start of the UDP
             * payload, so we need bump the pointer back to the start of the DMA
             * frame */
            decoded_buf &= ~(0xff);
            state->pending_tx[state->num_tx] = (void *) decoded_buf;
            state->num_tx++;
        }
        virtqueue_init_ring_object(&handle);
        more = virtqueue_get_used_buf(&state->tx_virtqueue, &handle, &len);
        if (once) {
            break;
        }
    }
}
#endif

static err_t lwip_eth_send(struct netif *netif, struct pbuf *p)
{
    err_t ret = ERR_OK;

    if (p->tot_len > BUFFER_SIZE) {
        ZF_LOGF("len %hu is invalid in lwip_eth_send", p->tot_len);
        return ERR_MEM;
    }

    state_t *state = (state_t *)netif->state;

#ifdef ZERO_COPY
    /*
     * If the largest pbuf is a custom pbuf and the remaining pbufs can
     * be packed around it into the allocation, they are copied into the
     * ethernet frame, otherwise we allocate a new buffer and copy
     * everything.
     */

    size_t copy_before = 0;
    size_t space_after = 0;
    ethernet_buffer_t *buffer = NULL;
    unsigned char *frame = NULL;
    for (struct pbuf *curr = p; curr != NULL; curr = curr->next) {
        if (frame == NULL && curr->flags & PBUF_FLAG_IS_CUSTOM) {
            /* We've reached a custom pbuf */
            lwip_custom_pbuf_t *custom = (lwip_custom_pbuf_t *) curr;

            uintptr_t payload = (uintptr_t)curr->payload;
            uintptr_t buffer_start = (uintptr_t)custom->buffer->buffer;
            uintptr_t buffer_end = buffer_start + custom->buffer->size;
            size_t space_before = payload - buffer_start;
            space_after = buffer_end - (payload + curr->len);

            if (space_before >= copy_before) {
                buffer = custom->buffer;
                frame = (void *)(payload - copy_before);
            }
        } else if (frame == NULL) {
            /* Haven't found a copy candidate yet */
            copy_before += curr->len;
        } else {
            /* Already found a copy candidate */
            if (space_after > curr->len) {
                space_after -= curr->len;
            } else {
                frame = NULL;
                buffer = NULL;
                break;
            }
        }
    }
#else
    ethernet_buffer_t *buffer = NULL;
    unsigned char *frame = NULL;
#endif

    /*
     * We need to allocate a new buffer if a suitable one wasn't found.
     */
    bool buffer_allocated = false;
    if (buffer == NULL) {
        buffer = alloc_buffer(state, p->tot_len);
        if (buffer == NULL) {
            ZF_LOGF("Out of ethernet memory");
            return ERR_MEM;
        }
        frame = buffer->buffer;
        buffer_allocated = true;
    }

    /* Copy all buffers that need to be copied */
    unsigned int copied = 0;
    for (struct pbuf *curr = p; curr != NULL; curr = curr->next) {
        unsigned char *buffer_dest = &frame[copied];
        if ((uintptr_t)buffer_dest != (uintptr_t)curr->payload) {
            /* Don't copy memory back into the same location */
            memcpy(buffer_dest, curr->payload, curr->len);
        }
        copied += curr->len;
    }

    mark_buffer_used(buffer);

    /* Send to available ring */
    virtqueue_ring_object_t avail_ring;
    virtqueue_init_ring_object(&avail_ring);
    int err = virtqueue_add_available_buf(
        &state->tx_virtqueue,
        &avail_ring,
        (void*)ENCODE_DMA_ADDRESS(frame),
        copied,
        VQ_RW
    );
    ZF_LOGF_IF(err == 0, "lwip_eth_send: Error while enqueuing available buffer, queue full");
    state->tx_queue_data[avail_ring.cur] = buffer;
    state->tx_virtqueue.notify();

error:
    if (buffer_allocated) {
        free_buffer(state, buffer);
    }
    return ret;

#if 0
    virtqueue_ring_object_t avail_ring;
    virtqueue_init_ring_object(&avail_ring);
    /* HACK: This is a bad hack that assumes all 2-chained pbufs are part of the
     * zero-copy solution */
    int num_pbufs = 0;
    for (struct pbuf *curr = p; curr != NULL; curr = curr->next) {
        num_pbufs++;
    }

    ZF_LOGF_IF(num_pbufs > 2, "Wot! More than 2 pbufs");
    if (!virtqueue_add_available_buf(&state->tx_virtqueue, &avail_ring,
                                     ENCODE_DMA_ADDRESS(buf), p->tot_len, VQ_RW)) {
        ZF_LOGF("lwip_eth_send: Error while enqueuing available buffer, queue full");
    }

    void *buf;
    if (num_pbufs == 2) {
        struct pbuf *first_pbuf = p;
        struct pbuf *second_pbuf = p->next;
        ZF_LOGF_IF(second_pbuf->flags & PBUF_FLAG_IS_CUSTOM == 0, "second pbuf not custom!");
        ZF_LOGF_IF((uintptr_t) second_pbuf->payload & 0xff != 42, "second pbuf not offset by 42!");
        ZF_LOGF_IF(first_pbuf->len != 42, "first pbuf not 42!");
        /* Get the start of the DMA buf */
        buf = (uintptr_t) second_pbuf->payload & (uintptr_t) (~(0xff));
        memcpy(buf, p->payload, 42);
    } else {
        /* Edge case where lwIP may decide to re-use the zero-copy buffer by
         * altering its headers */
        dataport_ptr_t ptr = dataport_wrap_ptr(p->payload);
        if (ptr.id != -1) {
            buf = p->payload;
        } else {
            if (state->num_tx == 0) {
                lwip_recycle_tx_bufs(state, true);
            }

            if (state->num_tx != 0) {
                state->num_tx--;
                buf = state->pending_tx[state->num_tx];
            } else {
                ZF_LOGF("ded");
                return ERR_MEM;
            }

            memcpy(buf, p->payload, p->len);
        }
    }

    assert(ENCODE_DMA_ADDRESS(buf));
    // ZF_LOGF_IF(ENCODE_DMA_ADDRESS(buf) == NULL, "encoded DMA buffer is
    // NULL");

    state->action = true;

    return ERR_OK;
#endif
}

#if 0
static void lwip_rx_free_buf(struct pbuf *buf)
{
    lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) buf;

    dataport_ptr_t wrapped_ptr = dataport_wrap_ptr(custom_pbuf->dma_buf);
    state_t *state = NULL;
    for (int i = 0; i < mapper_len; i++) {
        if (mapper[i].dataport_id == wrapped_ptr.id) {
            state = mapper[i].state;
            break;
        }
    }

    ZF_LOGF_IF(state == NULL, "state is NULL");

    if (!custom_pbuf->is_echo) {
        state->pending_tx[state->num_tx] = custom_pbuf->dma_buf;
        state->num_tx++;
    }

    if (state->num_tx > 30) {
        state->num_tx--;
        void *new_buf = state->pending_tx[state->num_tx];
        virtqueue_ring_object_t new_ring;
        virtqueue_init_ring_object(&new_ring);
        if (!virtqueue_add_available_buf(&state->rx_virtqueue, &new_ring, ENCODE_DMA_ADDRESS(new_buf), BUF_SIZE, VQ_RW)) {
            state->num_tx++;
            //ZF_LOGF_IF(state->num_tx > NUM_BUFS * 2, "Overruning state->pending_tx");
            //ZF_LOGF("Error while enqueuing available buffer, queue full");
        }
    }

    LWIP_MEMPOOL_FREE(RX_POOL, custom_pbuf);
}

/* Async driver will set a flag to signal that there is work to be done  */
static void lwip_eth_poll(state_t *state)
{
    /*
     * Pullss packets from the receive queue.
     *
     * Seem to be spending more time here than necessary.
     */
    assert(state);
    while (1) {
        virtqueue_ring_object_t handle;

        uint32_t len;

        /* Peek into the virtqueue without dequeuing */
        unsigned next = (state->rx_virtqueue.u_ring_last_seen + 1) &
            (state->rx_virtqueue.queue_len - 1);

        if (next == state->rx_virtqueue.used_ring->idx) {
            break;
        }

        handle.first = state->rx_virtqueue.used_ring->ring[next].id;
        len = state->rx_virtqueue.used_ring->ring[next].len;

        handle.cur = handle.first;

        uint64_t buf;
        vq_flags_t flag;
        int more = virtqueue_gather_used(&state->rx_virtqueue, &handle, &buf, &len, &flag);
        if (more == 0) {
            ZF_LOGF("pico_eth_poll: Invalid virtqueue ring entry");
        }
        assert(DECODE_DMA_ADDRESS(buf));
        //ZF_LOGF_IF(DECODE_DMA_ADDRESS(buf) == NULL, "decoded DMA buffer is NULL");

        err_t err = ERR_OK;
        struct pbuf *p = NULL;
        if (len > 0) {
            /* Zero-copy RX */
            lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) LWIP_MEMPOOL_ALLOC(RX_POOL);
            assert(custom_pbuf != NULL);
            custom_pbuf->p.custom_free_function = lwip_rx_free_buf;
            //ZF_LOGE("poll dma_buf = %x", DECODE_DMA_ADDRESS(buf));
            custom_pbuf->dma_buf = DECODE_DMA_ADDRESS(buf);
            custom_pbuf->is_echo = false;
            struct pbuf *p = pbuf_alloced_custom(PBUF_RAW, len, PBUF_REF, &custom_pbuf->p, custom_pbuf->dma_buf, BUF_SIZE);
            err = state->netif.input(p, &state->netif);
            if (err != ERR_OK) {
                /* Free the pbuf in the common code path instead */
                break;
            }
        }

        virtqueue_get_used_buf(&state->rx_virtqueue, &handle, &len);
        if (err != ERR_OK && p != NULL) {
            ZF_LOGE("Failed to give pbuf to lwIP");
            pbuf_free(p);
        }
    }
}

static void notify_server(UNUSED seL4_Word badge, void *cookie)
{
    state_t *state = cookie;
    if (state->action) {
        state->action = false;
        state->tx_virtqueue.notify();
    }
}

static void irq_from_ethernet(UNUSED seL4_Word badge, void *cookie)
{
    assert(cookie);
    state_t *data = cookie;
    lwip_recycle_tx_bufs(data, false);
    lwip_eth_poll(data);
}
#endif

static inline err_t do_netif_input(struct netif *netif, struct pbuf *p)
{
    return netif->input(p, netif);
}

static void rx_queue_notify(seL4_Word badge, void *cookie)
{
    /* New packets have been received. */
    state_t *state = cookie;
    virtqueue_ring_object_t handle;

    int used_len;
    while (virtqueue_get_used_buf(&state->rx_virtqueue, &handle, &used_len)) {
        int index = handle.cur;
        void *buf;
        unsigned len;
        vq_flags_t flag;
        while (virtqueue_gather_used(&state->rx_virtqueue, &handle, &buf, &len, &flag)) {
            ethernet_buffer_t *buffer = state->rx_queue_data[index];
            state->rx_queue_data[index] = NULL;
            struct pbuf *p = create_interface_buffer(state, buffer, len);

            if (do_netif_input(&state->netif, p) != ERR_OK) {
                /* If it is successfully received, the receiver controls
                 * whether or not it gets freed. */
                pbuf_free(p);
            }

            index = handle.cur;
        }
    }
}


static void tx_queue_notify(seL4_Word badge, void *cookie)
{
    /* Packets have been sent. */
    state_t *state = cookie;
    virtqueue_ring_object_t handle;

    int used_len;
    while (virtqueue_get_used_buf(&state->tx_virtqueue, &handle, &used_len)) {
        int index = handle.cur;
        void *buf;
        unsigned len;
        vq_flags_t flag;
        while (virtqueue_gather_used(&state->tx_virtqueue, &handle, &buf, &len, &flag)) {
            ethernet_buffer_t *buffer = state->tx_queue_data[index];
            state->tx_queue_data[index] = NULL;
            mark_buffer_unused(state, buffer);

            index = handle.cur;
        }
    }
}

static err_t ethernet_init(struct netif *netif)
{
    if (netif->state == NULL) {
        return ERR_ARG;
    }

    state_t *data = netif->state;

    netif->hwaddr[0] = data->mac[0];
    netif->hwaddr[1] = data->mac[1];
    netif->hwaddr[2] = data->mac[2];
    netif->hwaddr[3] = data->mac[3];
    netif->hwaddr[4] = data->mac[4];
    netif->hwaddr[5] = data->mac[5];
    netif->mtu = ETHER_MTU;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->output = etharp_output;
    netif->linkoutput = lwip_eth_send;
    NETIF_INIT_SNMP(netif, snmp_ifType_ethernet_csmacd, LINK_SPEED);
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_IGMP;

    return ERR_OK;
}

int lwip_ethernet_async_client_init_late(void *cookie, register_callback_handler_fn_t register_handler)
{
#if 0
    state_t *data = cookie;
    register_handler(0, "lwip_notify_ethernet", notify_server, data);
#endif

    return 0;
}

int lwip_ethernet_async_client_init(ps_io_ops_t *io_ops, const char *tx_virtqueue, const char *rx_virtqueue,
                                    register_callback_handler_fn_t register_handler, get_mac_client_fn_t get_mac, void **cookie)
{
    state_t *data;
    int error = ps_calloc(
        &io_ops->malloc_ops,
        1,
        sizeof(*data),
        (void **)&data
    );
    ZF_LOGF_IF(error != 0, "Unable to ethernet state");
    data->io_ops = io_ops;

    seL4_Word tx_badge;
    seL4_Word rx_badge;
    /* Initialise read virtqueue */
    error = camkes_virtqueue_driver_init_with_recv(
        &data->tx_virtqueue,
        camkes_virtqueue_get_id_from_name(tx_virtqueue),
        NULL,
        &tx_badge
    );
    if (error) {
        ZF_LOGE("Unable to initialise serial server read virtqueue");
    }

    /* Initialise write virtqueue */
    error = camkes_virtqueue_driver_init_with_recv(
        &data->rx_virtqueue,
        camkes_virtqueue_get_id_from_name(rx_virtqueue),
        NULL,
        &rx_badge
    );
    if (error) {
        ZF_LOGE("Unable to initialise serial server write virtqueue");
    }

    error = ps_calloc(
        &io_ops->malloc_ops,
        data->rx_virtqueue.queue_len,
        sizeof(data->rx_queue_data[0]),
        (void **)&data->rx_queue_data
    );
    ZF_LOGF_IF(error != 0, "Unable to allocate RX queue metadata");

    error = ps_calloc(
        &io_ops->malloc_ops,
        data->tx_virtqueue.queue_len,
        sizeof(data->tx_queue_data[0]),
        (void **)&data->tx_queue_data
    );
    ZF_LOGF_IF(error != 0, "Unable to allocate TX queue metadata");

    /* preallocate buffers */

    for (int i = 0; i < NUM_BUFFERS - 1; i++) {
        void *buf = ps_dma_alloc(
            &io_ops->dma_manager,
            BUFFER_SIZE,
            64,
            1,
            PS_MEM_NORMAL
        );
        assert(buf);
        memset(buf, 0, BUFFER_SIZE);
        ZF_LOGF_IF(buf == NULL, "Failed to allocate DMA memory for pending rx ring");

        virtqueue_ring_object_t handle;
        virtqueue_init_ring_object(&handle);
        ethernet_buffer_t *buffer = &data->buffer_metadata[i];
        &data->buffer_metadata[i];
        *buffer = (ethernet_buffer_t) {
            .buffer = buf,
            .dma_addr = ENCODE_DMA_ADDRESS(buf),
            .size = BUFFER_SIZE,
            .origin = ORIGIN_RX_QUEUE,
            .allocated = false,
            .in_async_use = false,
        };
        int err = virtqueue_add_available_buf(
            &data->rx_virtqueue,
            &handle,
            (void *)buffer->dma_addr,
            buffer->size,
            VQ_RW
        );
        if (err == 0) {
            // ps_dma_free(&io_ops->dma_manager, buf, BUFFER_SIZE);
            break;
        }
        data->rx_queue_data[handle.cur] = buffer;
    }
    data->rx_virtqueue.notify();

    data->num_available_tx = 0;
    for (int i = 0; i < NUM_BUFFERS && i < data->tx_virtqueue.queue_len; i++) {
        void *buf = ps_dma_alloc(
            &io_ops->dma_manager,
            BUFFER_SIZE,
            64,
            1,
            PS_MEM_NORMAL
        );
        assert(buf);
        memset(buf, 0, BUFFER_SIZE);
        ZF_LOGF_IF(buf == NULL, "Failed to allocate DMA memory for pending tx ring");

        ethernet_buffer_t *buffer = &data->buffer_metadata[i + NUM_BUFFERS];
        *buffer = (ethernet_buffer_t) {
            .buffer = buf,
            .dma_addr = ENCODE_DMA_ADDRESS(buf),
            .size = BUFFER_SIZE,
            .origin = ORIGIN_TX_QUEUE,
            .allocated = false,
            .in_async_use = false,
        };

        data->available_tx[data->num_available_tx] = buffer;
        data->num_available_tx += 1;
    }

    register_handler(tx_badge, "lwip_irq_from_ethernet", tx_queue_notify, data);
    register_handler(rx_badge, "lwip_irq_from_ethernet", rx_queue_notify, data);

    LWIP_MEMPOOL_INIT(RX_POOL);

    get_mac(&data->mac[0], &data->mac[1], &data->mac[2], &data->mac[3], &data->mac[4], &data->mac[5]);

    /* Set some dummy IP configuration values to get lwIP bootstrapped  */
    struct ip4_addr netmask, ipaddr, gw, multicast;
    ipaddr_aton("0.0.0.0", &gw);
    ipaddr_aton("0.0.0.0", &ipaddr);
    ipaddr_aton("0.0.0.0", &multicast);
    ipaddr_aton("255.255.255.0", &netmask);

    data->netif.name[0] = 'e';
    data->netif.name[1] = '0';

    netif_add(&data->netif, &ipaddr, &netmask, &gw, data,
              ethernet_init, ethernet_input);
    netif_set_default(&data->netif);
    data->tx_virtqueue.notify();

    *cookie = data;
    return 0;
}
