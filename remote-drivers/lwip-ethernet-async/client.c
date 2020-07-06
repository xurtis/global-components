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

#include <string.h>
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

#define NUM_BUFS 256
#define BUF_SIZE 2048

// TODO Add functionality to query for Ethernet device's link speed
#define LINK_SPEED 1000000000 // Gigabit

typedef struct state {
    struct netif netif;

    /* keeps track of how many TX buffers are in use */
    int num_tx;
    /*
     * this represents the pool of buffers that can be used for TX,
     * this array is a sliding array in that num_tx acts a pointer to
     * separate between buffers that are in use and buffers that are
     * not in use. E.g. 'o' = free, 'x' = in use
     *  -------------------------------------
     *  | o | o | o | o | o | o | x | x | x |
     *  -------------------------------------
     *                          ^
     *                        num_tx
     */
    void *pending_tx[NUM_BUFS];

    /* mac address for this client */
    uint8_t mac[6];
    virtqueue_driver_t tx_virtqueue;
    virtqueue_driver_t rx_virtqueue;
    ps_io_ops_t *io_ops;
    bool action;
} state_t;

struct id_state_mapper {
    uint32_t dataport_id;
    state_t *state;
};

static struct id_state_mapper *mapper;
static size_t mapper_len;

typedef struct lwip_custom_pbuf {
    struct pbuf_custom p;
    void *dma_buf;
} lwip_custom_pbuf_t;
LWIP_MEMPOOL_DECLARE(RX_POOL, NUM_BUFS, sizeof(lwip_custom_pbuf_t), "Zero-copy RX pool");

/* 1500 is the standard ethernet MTU at the network layer. */
#define ETHER_MTU 1500

static err_t lwip_eth_send(struct netif *netif, struct pbuf *p)
{
    state_t *state = (state_t *)netif->state;

    virtqueue_ring_object_t handle;
    uint32_t sent_len;
    void *buf;
    if (virtqueue_get_used_buf(&state->tx_virtqueue, &handle, &sent_len) == 0) {
        if (state->num_tx != 0) {
            state->num_tx--;
            buf = state->pending_tx[state->num_tx];
        } else {
            // No free packets to use.
            return ERR_MEM;
        }
    } else {
        vq_flags_t flag;
        int more = virtqueue_gather_used(&state->tx_virtqueue, &handle, &buf, &sent_len, &flag);
        if (more == 0) {
            ZF_LOGF("pico_eth_send: Invalid virtqueue ring entry");
        }

        buf = DECODE_DMA_ADDRESS(buf);
    }

    /* copy the packet over */
    pbuf_copy_partial(p, buf, p->tot_len, 0);
    ps_dma_cache_clean(&state->io_ops->dma_manager, buf, p->tot_len);

    virtqueue_init_ring_object(&handle);
    if (!virtqueue_add_available_buf(&state->tx_virtqueue, &handle, ENCODE_DMA_ADDRESS(buf), p->tot_len, VQ_RW)) {
        ZF_LOGF("pico_eth_send: Error while enqueuing available buffer, queue full");
    }
    state->action = true;

    LINK_STATS_INC(link.xmit);

    return ERR_OK;
}

static void lwip_free_buf(struct pbuf *buf)
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

    virtqueue_ring_object_t handle;
    virtqueue_init_ring_object(&handle);
    if (!virtqueue_add_available_buf(&state->rx_virtqueue, &handle, ENCODE_DMA_ADDRESS(custom_pbuf->dma_buf), BUF_SIZE,
                                     VQ_RW)) {
        ZF_LOGF("Error while enqueuing available buffer");
    }
    LWIP_MEMPOOL_FREE(RX_POOL, custom_pbuf);
}

/* Async driver will set a flag to signal that there is work to be done  */
static void lwip_eth_poll(state_t *state)
{
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

        void *buf;
        vq_flags_t flag;
        int more = virtqueue_gather_used(&state->rx_virtqueue, &handle, &buf, &len, &flag);
        if (more == 0) {
            ZF_LOGF("pico_eth_poll: Invalid virtqueue ring entry");
        }

        err_t err = ERR_OK;
        struct pbuf *p = NULL;
        if (len > 0) {
            ps_dma_cache_invalidate(&state->io_ops->dma_manager, DECODE_DMA_ADDRESS(buf), len);
            /* Zero-copy RX */
            lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) LWIP_MEMPOOL_ALLOC(RX_POOL);
            assert(custom_pbuf != NULL);
            custom_pbuf->p.custom_free_function = lwip_free_buf;
            custom_pbuf->dma_buf = DECODE_DMA_ADDRESS(buf);
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
    /* NOTE: Check timeouts instead? */
    lwip_eth_poll(data);
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
    state_t *data = cookie;
    register_handler(0, "lwip_notify_ethernet", notify_server, data);
    return 0;
}

int lwip_ethernet_async_client_init(ps_io_ops_t *io_ops, const char *tx_virtqueue, const char *rx_virtqueue,
                                    register_callback_handler_fn_t register_handler, get_mac_client_fn_t get_mac, void **cookie)
{
    state_t *data;
    int error = ps_calloc(&io_ops->malloc_ops, 1, sizeof(*data), (void **)&data);
    data->io_ops = io_ops;

    seL4_Word tx_badge;
    seL4_Word rx_badge;
    /* Initialise read virtqueue */
    error = camkes_virtqueue_driver_init_with_recv(&data->tx_virtqueue, camkes_virtqueue_get_id_from_name(tx_virtqueue),
                                                   NULL, &tx_badge);
    if (error) {
        ZF_LOGE("Unable to initialise serial server read virtqueue");
    }

    /* Initialise write virtqueue */
    error = camkes_virtqueue_driver_init_with_recv(&data->rx_virtqueue, camkes_virtqueue_get_id_from_name(rx_virtqueue),
                                                   NULL, &rx_badge);
    if (error) {
        ZF_LOGE("Unable to initialise serial server write virtqueue");
    }

    bool add_to_mapper = false;
    /* preallocate buffers */
    for (int i = 0; i < NUM_BUFS - 1; i++) {
        void *buf = ps_dma_alloc(&io_ops->dma_manager, BUF_SIZE, 4, 1, PS_MEM_NORMAL);
        assert(buf);
        memset(buf, 0, BUF_SIZE);
        virtqueue_ring_object_t handle;

        virtqueue_init_ring_object(&handle);

        /* Save the dataport ID to state data mapping for later.
           pico_free_buf doesn't allow us to provide a cookie so we need to be able
           to get from a dma pointer back to the driver state.
         */
        if (!add_to_mapper) {
            dataport_ptr_t wrapped_ptr = dataport_wrap_ptr(buf);
            mapper = realloc(mapper, mapper_len + 1);
            mapper[mapper_len] = (struct id_state_mapper) {
                .dataport_id = wrapped_ptr.id, .state = data
            };
            mapper_len++;
            add_to_mapper = true;
        }
        if (!virtqueue_add_available_buf(&data->rx_virtqueue, &handle, ENCODE_DMA_ADDRESS(buf), BUF_SIZE, VQ_RW)) {
            ZF_LOGF("Error while enqueuing available buffer, queue full");
        }
    }

    for (int i = 0; i < NUM_BUFS - 1; i++) {
        void *buf = ps_dma_alloc(&io_ops->dma_manager, BUF_SIZE, 4, 1, PS_MEM_NORMAL);
        ZF_LOGF_IF(buf == NULL, "Failed to allocate DMA memory for pending tx ring");
        memset(buf, 0, BUF_SIZE);
        data->pending_tx[data->num_tx] = buf;
        data->num_tx++;
    }
    register_handler(tx_badge, "lwip_irq_from_ethernet", irq_from_ethernet, data);

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

    printf("Installed a netif into lwip\n");
    data->tx_virtqueue.notify();
    *cookie = data;
    return 0;
}
