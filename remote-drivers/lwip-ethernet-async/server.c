/*
 * Copyright 2020, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */

#include <autoconf.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <camkes/dma.h>
#include <camkes/dataport.h>
#include <camkes/io.h>
#include <camkes/irq.h>
#include <camkes/virtqueue.h>

#include <platsupport/io.h>
#include <platsupport/irq.h>
#include <platsupport/interface_registration.h>
#include <ethdrivers/raw.h>
#include <ethdrivers/intel.h>
#include <sel4utils/sel4_zf_logif.h>
#include <virtqueue.h>
#include <lwip-ethernet-async.h>

#include <utils/util.h>

#define BULK_TX_SIZE 32
static uintptr_t phys_ring[BULK_TX_SIZE];
static unsigned int len_ring[BULK_TX_SIZE];

typedef struct tx_cookie {
    size_t num_handles;
    uint32_t first_idx;
} tx_cookie_t;

typedef struct data {
    ps_io_ops_t *io_ops;
    virtqueue_device_t tx_virtqueue;
    virtqueue_device_t rx_virtqueue;
    uint8_t hw_mac[6];
    struct eth_driver *eth_driver;
} server_data_t;

#define BUF_SIZE 2048

static void eth_tx_complete(void *iface, void *cookie)
{
    server_data_t *state = iface;
    uint32_t first = (uint32_t) ((uintptr_t) cookie);

    virtqueue_ring_object_t handle;
    handle.first = first;
    handle.cur = first;

    void *buf;
    unsigned len;
    vq_flags_t flag;
    int index = handle.cur;
    while (virtqueue_gather_available(&state->tx_virtqueue, &handle, &buf, &len, &flag)) {
        virtqueue_ring_object_t free_handle = {
            .first = index,
            .cur = index,
        };
        int err = virtqueue_add_used_buf(&state->tx_virtqueue, &free_handle, len);
        ZF_LOGF_IF(err == 0, "eth_tx_complete: Error while enqueuing used buffer, queue full");
        index = handle.cur;
    }

    /* Notify that packets have been transmitted or dropped and buffers can be
     * reused */
    state->tx_virtqueue.notify();
}

static uintptr_t eth_allocate_rx_buf(void *iface, size_t buf_size, void **cookie)
{
    if (buf_size > BUF_SIZE) {
        return 0;
    }
    server_data_t *state = iface;

    virtqueue_ring_object_t handle;

    if (virtqueue_get_available_buf(&state->rx_virtqueue, &handle) == 0) {
        // No buffer available to fill RX ring with.
        return 0;
    }

    void *buf;
    unsigned len;
    vq_flags_t flag;
    int more = virtqueue_gather_available(&state->rx_virtqueue, &handle, &buf, &len, &flag);
    if (more == 0) {
        ZF_LOGF("eth_allocate_rx_buf: Invalid virtqueue ring entry");
    }

    void *decoded_buf = DECODE_DMA_ADDRESS(buf);
    ZF_LOGF_IF(decoded_buf == NULL, "decoded DMA buffer is NULL");
    *cookie = (void *)(uintptr_t) handle.first;
    ps_dma_cache_invalidate(&state->io_ops->dma_manager, decoded_buf, buf_size);
    uintptr_t phys = ps_dma_pin(&state->io_ops->dma_manager, decoded_buf, buf_size);
    return phys;
}

static void eth_rx_complete(void *iface, unsigned int num_bufs, void **cookies, unsigned int *lens)
{
    server_data_t *state = iface;
    for (int i = 0; i < num_bufs; i++) {
        virtqueue_ring_object_t handle;
        handle.first = (uintptr_t)cookies[i];
        handle.cur = (uintptr_t)cookies[i];
        int err = virtqueue_add_used_buf(&state->rx_virtqueue, &handle, lens[i]);
        ZF_LOGF_IF(err == 0, "eth_rx_complete: Error while enqueuing used buffer, queue full");
    }

    // Notify that we've added received packets
    state->rx_virtqueue.notify();
    return;
}

static struct raw_iface_callbacks ethdriver_callbacks = {
    .tx_complete = eth_tx_complete,
    .rx_complete = eth_rx_complete,
    .allocate_rx_buf = eth_allocate_rx_buf
};

static void client_get_mac(uint8_t *b1, uint8_t *b2, uint8_t *b3, uint8_t *b4, uint8_t *b5, uint8_t *b6, void *cookie)
{
    server_data_t *state = cookie;
    *b1 = state->hw_mac[0];
    *b2 = state->hw_mac[1];
    *b3 = state->hw_mac[2];
    *b4 = state->hw_mac[3];
    *b5 = state->hw_mac[4];
    *b6 = state->hw_mac[5];
}

static void rx_queue_notify(seL4_Word badge, void *cookie)
{
    /* More available buffers so we poll to refill */
    server_data_t *state = cookie;

    state->eth_driver->i_fn.raw_poll(state->eth_driver);
}

static void tx_queue_notify(seL4_Word badge, void *cookie)
{
    /* We have packets that need to be sent */
    server_data_t *state = cookie;

    virtqueue_ring_object_t handle;
    while (virtqueue_get_available_buf(&state->tx_virtqueue, &handle)) {
        void *buf;
        unsigned len;
        vq_flags_t flag;

        /*
         * If the largest pbuf is a custom pbuf and the remaining pbufs can
         * be packed around it into the allocation, they are copied into the
         * ethernet frame, otherwise we allocate a new buffer and copy
         * everything.
         */

        size_t collected = 0;
        while (virtqueue_gather_available(&state->tx_virtqueue, &handle, &buf, &len, &flag)) {
            void *decoded_buf = DECODE_DMA_ADDRESS(buf);
            ZF_LOGF_IF(decoded_buf == NULL, "decoded DMA buffer is NULL");

            /* HACK: Align the buffers for any zero-copy buffers
             * The sabre platform requires that buffers have to be aligned to
             * 8-bytes, so we memmove the contents of the buffer to the start of
             * the DMA frame which should be aligned to a 2048 boundary */
            void *moved_buf = (void *)(((uintptr_t)decoded_buf) & (8 - 1));
            if (((uintptr_t)decoded_buf) & (8 - 1)) {
                memmove(moved_buf, decoded_buf, len);
                decoded_buf = moved_buf;
            }

            phys_ring[collected] = ps_dma_pin(&state->io_ops->dma_manager, decoded_buf, len);
            len_ring[collected] = len;
            ps_dma_cache_clean(&state->io_ops->dma_manager, decoded_buf, len);

            collected += 1;
            if (collected > BULK_TX_SIZE) {
                // Drop the packet as it is in too many parts
                collected = 0;
                break;
            }
        }

        int err;
        if (collected > 0) {
            err = state->eth_driver->i_fn.raw_tx(state->eth_driver, collected, phys_ring, len_ring, (void *)handle.first);
        }

        if (collected == 0 || err != ETHIF_TX_ENQUEUED) {
            eth_tx_complete(state, (void *)handle.first);
        }
    }
}

static int hardware_interface_searcher(void *cookie, void *interface_instance, char **properties)
{

    server_data_t *state = cookie;
    state->eth_driver = interface_instance;
    return PS_INTERFACE_FOUND_MATCH;
}

int lwip_ethernet_async_server_init(ps_io_ops_t *io_ops, const char *tx_virtqueue, const char *rx_virtqueue,
                                    register_callback_handler_fn_t register_handler, register_get_mac_server_fn register_get_mac_fn)
{

    server_data_t *data;
    int error = ps_calloc(&io_ops->malloc_ops, 1, sizeof(*data), (void **)&data);
    data->io_ops = io_ops;


    error = ps_interface_find(&io_ops->interface_registration_ops,
                              PS_ETHERNET_INTERFACE, hardware_interface_searcher, data);
    if (error) {
        ZF_LOGF("Unable to find an ethernet device");
    }

    data->eth_driver->cb_cookie = data;
    data->eth_driver->i_cb = ethdriver_callbacks;

    seL4_Word tx_badge;
    seL4_Word rx_badge;

    /* Initialise read virtqueue */
    error = camkes_virtqueue_device_init_with_recv(&data->tx_virtqueue, camkes_virtqueue_get_id_from_name(tx_virtqueue),
                                                   NULL, &tx_badge);
    if (error) {
        ZF_LOGE("Unable to initialise serial server read virtqueue");
    }
    /* Initialise write virtqueue */
    error = camkes_virtqueue_device_init_with_recv(&data->rx_virtqueue, camkes_virtqueue_get_id_from_name(rx_virtqueue),
                                                   NULL, &rx_badge);
    if (error) {
        ZF_LOGE("Unable to initialise serial server write virtqueue");
    }

    error = register_handler(tx_badge, "lwip_tx_irq", tx_queue_notify, data);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }
    error = register_handler(rx_badge, "lwip_rx_irq", rx_queue_notify, data);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }
    rx_queue_notify(rx_badge, data);

    data->eth_driver->i_fn.get_mac(data->eth_driver, data->hw_mac);
    data->eth_driver->i_fn.raw_poll(data->eth_driver);

    register_get_mac_fn(client_get_mac, data);
    return 0;
}
