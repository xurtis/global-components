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

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <camkes/msgqueue.h>
#include <camkes/virtqueue.h>
#include <utils/util.h>
#include <lwip/init.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <netif/etharp.h>
#include <lwip/dhcp.h>
#include <lwip/ip_addr.h>
#include <lwip/timeouts.h>
#include <lwipserver.h>
#include <lwip-socket-sync.h>
#include <platsupport/io.h>

#define LWIPSERVER_MAX_SOCKETS 32
#define LWIPSERVER_MAX_PENDING 32

typedef enum protocol_type {
    UDP,
    TCP
} protocol_type_t;

typedef struct pbuf_chain {
    struct pbuf *p;
    u16_t packet_pointer; // 'File' pointer of a pbuf
    /* The following two fields are only valid for UDP-based pbufs */
    ip_addr_t ip_addr;
    u16_t port;
    struct pbuf_chain *next;
} pbuf_chain_t;

typedef struct lwipserver_socket_async {
    /* Number of UDP packets enqueued, or 1 if any TCP data is pending */
    size_t rx_pending;
    /* Queued empty packets to receive data into */
    tx_msg_t *rx_pending_queue;
    tx_msg_t *rx_pending_queue_end;
    /* Pending packets to send */
    tx_msg_t *tx_pending_queue;
    tx_msg_t *tx_pending_queue_end;
} lwipserver_socket_async_t;

typedef struct lwipserver_socket {
    seL4_Word client_id;
    int socket_fd;
    bool in_use;
    protocol_type_t proto;
    /* Proto determines which one of the union is valid */
    union {
        struct tcp_pcb *tcp_pcb;
        struct udp_pcb *udp_pcb;
    };
    pbuf_chain_t *pbufs;
    pbuf_chain_t *pbuf_tail;
    lwipserver_event_type_t outstanding_events;
    lwipserver_socket_async_t *async_socket;
} lwipserver_socket_t;

seL4_Word lwip_control_get_sender_id();

static int emit_client;
static int emit_client_async;
static ps_malloc_ops_t *malloc_ops;
static lwipserver_socket_t socket_array[LWIPSERVER_MAX_SOCKETS];
static struct tcp_pcb *pending_connections[LWIPSERVER_MAX_PENDING];
static int pending_head;
static int pending_tail;
static int pending_num;
static camkes_msgqueue_sender_t event_sender;
static virtqueue_device_t tx_virtqueue;
static virtqueue_device_t rx_virtqueue;
static int curr_socket_fd;

extern void *ethdriver_buf;

static inline int find_next_socket_id(void)
{
    for (int i = 0; i < LWIPSERVER_MAX_SOCKETS; i++) {
        if (!socket_array[curr_socket_fd].in_use) {
            int ret = curr_socket_fd;
            curr_socket_fd = (curr_socket_fd + 1) % LWIPSERVER_MAX_SOCKETS;
            return ret;
        }
        curr_socket_fd = (curr_socket_fd + 1) % LWIPSERVER_MAX_SOCKETS;
    }
    ZF_LOGE("Ran out of socket IDs");
    return -1;
}

static inline int server_check_common(int socket_fd)
{
    if (socket_fd < 0 || socket_fd >= LWIPSERVER_MAX_SOCKETS) {
        ZF_LOGE("Socket ID is invalid");
        return -EINVAL;
    }

    if (!socket_array[socket_fd].in_use) {
        ZF_LOGE("Socket has not been opened yet!");
        return -EINVAL;
    }

    return 0;
}

static void pop_pbuf_from_chain(lwipserver_socket_t *socket)
{
    pbuf_chain_t *head = socket->pbufs;
    socket->pbufs = head->next;
    if (head->next == NULL) {
        socket->pbuf_tail = NULL;
    }
    //trace_extra_point_start(4 + 13);
    pbuf_free(head->p);
    //trace_extra_point_end(4 + 13, 1);
    ZF_LOGF_IF(ps_free(malloc_ops, sizeof(*head), head),
               "Failed to free a pbuf_chain_t node");
}

static int copy_tcp_socket_packets(int socket_fd, void *user_buffer, int len)
{
    int bytes_copied = 0;

    pbuf_chain_t *curr_pbuf = socket_array[socket_fd].pbufs;
    pbuf_chain_t *prev_pbuf = NULL;

    while (curr_pbuf != NULL && bytes_copied < len) {
        assert(curr_pbuf->p != NULL);
        u16_t bytes_copied_now = pbuf_copy_partial(curr_pbuf->p, user_buffer + bytes_copied,
                                                   len - bytes_copied,
                                                   curr_pbuf->packet_pointer);
        prev_pbuf = curr_pbuf;
        curr_pbuf = curr_pbuf->next;
        if ((bytes_copied_now + prev_pbuf->packet_pointer) < prev_pbuf->p->tot_len) {
            prev_pbuf->packet_pointer += bytes_copied_now;
        } else {
            assert((prev_pbuf->packet_pointer + bytes_copied_now) >= prev_pbuf->p->tot_len);
            pop_pbuf_from_chain(&socket_array[socket_fd]);
        }
        bytes_copied += bytes_copied_now;
    }

    return bytes_copied;
}

static int copy_udp_socket_packets(int socket_fd, void *user_buffer, int len,
                                   ip_addr_t *ret_addr, u16_t *ret_port)
{
    pbuf_chain_t *curr_pbuf = socket_array[socket_fd].pbufs;

    if (curr_pbuf == NULL) {
        return 0;
    }

    /* Try to copy the entire packet contents, otherwise get as much as we can and drop the
     * packet */

    //trace_extra_point_start(4 + 11);
    u16_t bytes_copied = pbuf_copy_partial(curr_pbuf->p, user_buffer, len, 0);
    //trace_extra_point_end(4 + 11, 1);

    if (ret_addr) {
        *ret_addr = curr_pbuf->ip_addr;
    }

    if (ret_port) {
        *ret_port = curr_pbuf->port;
    }

    /* Drop the packet now */
    pop_pbuf_from_chain(&socket_array[socket_fd]);

    return (int) bytes_copied;
}

static void tx_complete(void *cookie, int len)
{
    //trace_extra_point_start(4 + 15);
    virtqueue_ring_object_t handle;
    handle.first = (uint32_t)(uintptr_t)cookie;
    handle.cur = (uint32_t)(uintptr_t)cookie;

    if (!virtqueue_add_used_buf(&tx_virtqueue, &handle, len)) {
        ZF_LOGE("TX: Error while enqueuing available buffer");

    }

    emit_client_async = 1;
    //trace_extra_point_end(4 + 15, 1);
}

static void tx_socket(lwipserver_socket_t *socket)
{
    //trace_extra_point_start(4 + 2);
    assert(socket != NULL);

    if (socket->async_socket == NULL) {
        //trace_extra_point_end(4 + 2, 1);
        ZF_LOGE("Socket isn't setup for async");
        return;
    }

    while (socket->async_socket->tx_pending_queue) {
        ZF_LOGF_IF(socket->async_socket->tx_pending_queue_end == NULL,
                   "Inconsistent queue state");
        err_t error;
        tx_msg_t *msg = socket->async_socket->tx_pending_queue;
        struct pbuf *p = NULL;

        if (socket->proto == UDP) {
            //trace_extra_point_start(4 + 24);
            p = pbuf_alloc_reference(msg->buf_ref, msg->total_len, PBUF_REF);
            //trace_extra_point_end(4 + 24, 1);
            if (p != NULL) {
                //trace_extra_point_start(4 + 5);
                error = udp_sendto(socket->udp_pcb, p, &msg->src_addr, msg->src_port);
                //trace_extra_point_end(4 + 5, 1);
            } else {
                error = ERR_MEM;
            }
        } else {
            //error = tcp_write(socket->tcp_pcb, msg->buf + msg->done_len,
                              //msg->total_len - msg->done_len, TCP_WRITE_FLAG_COPY);
        }

        if (p != NULL) {
            //trace_extra_point_start(4 + 19);
            pbuf_free(p);
            //trace_extra_point_end(4 + 19, 1);
        }

        if (error != ERR_OK) {
            /*  Free the internal tx buffer in case tx fails. Up to the client to
             *  retry the trasmission */
            ZF_LOGE("tx main: This shouldn't happen. Handle error case");
            msg->done_len = -1;
            socket->async_socket->tx_pending_queue = msg->next;
            if (socket->async_socket->tx_pending_queue_end == msg) {
                socket->async_socket->tx_pending_queue_end = NULL;
            }
            tx_complete(msg->cookie_save, 0);
            continue;
        }

        msg->done_len = msg->total_len;
        socket->async_socket->tx_pending_queue = msg->next;
        if (socket->async_socket->tx_pending_queue_end == msg) {
            socket->async_socket->tx_pending_queue_end = NULL;
        }
        tx_complete(msg->cookie_save, msg->total_len);
    }
    //trace_extra_point_end(4 + 2, 1);
}

static void tx_queue_handle(void)
{
    //trace_extra_point_start(4 + 1);
    //trace_extra_point_start(3);
    int error;
    err_t ret;

    while (1) {
        //trace_extra_point_start(4);
        virtqueue_ring_object_t handle;
        if (virtqueue_get_available_buf(&tx_virtqueue, &handle) == 0) {
            //trace_extra_point_end(4, 1);
            break;
        }

        uint64_t buf;
        unsigned len;
        vq_flags_t flag;
        int more = virtqueue_gather_available(&tx_virtqueue, &handle, &buf, &len, &flag);
        if (more == 0) {
            ZF_LOGE("No message received");
            //trace_extra_point_end(4, 1);
            break;
        }

        tx_msg_t *msg = camkes_virtqueue_device_offset_to_buffer(&tx_virtqueue, buf);
        ZF_LOGF_IF(msg == NULL, "msg is null");
        ZF_LOGF_IF((msg->total_len > 1400) || (msg->total_len == 0),
                   "bad msg len in tx %zd", msg->total_len);
        //trace_extra_point_end(4, 1);

        //trace_extra_point_start(5);
        error = server_check_common(msg->socket_fd);
        if (error) {
            ZF_LOGE("Socket is null");
            msg->done_len = -1;
            tx_complete((void*)(uintptr_t)handle.first, 0);
            //trace_extra_point_end(5, 1);
            continue;
        }

        lwipserver_socket_t *socket = &socket_array[msg->socket_fd];

        if (socket->async_socket == NULL) {
            ZF_LOGE("Socket isn't setup for async");
            msg->done_len = -1;
            tx_complete((void*)(uintptr_t)handle.first, 0);
            //trace_extra_point_end(5, 1);
            continue;

        }

        if (socket->async_socket->tx_pending_queue) {
            ZF_LOGF_IF(socket->async_socket->tx_pending_queue_end == NULL,
                       "Inconsistent queue state");
            socket->async_socket->tx_pending_queue_end->next = msg;
            socket->async_socket->tx_pending_queue_end = msg;
            msg->next = NULL;
            msg->cookie_save = (void*)(uintptr_t)handle.first;
            //trace_extra_point_end(5, 1);
            continue;
        }
        //trace_extra_point_end(5, 1);

        struct pbuf *p = NULL;

        if (socket->proto == UDP) {
            //trace_extra_point_start(6);
            //trace_extra_point_start(4 + 24);
            p = pbuf_alloc_reference(msg->buf_ref, msg->total_len,
                                     PBUF_REF);
            //trace_extra_point_end(4 + 24, 1);
            if (p != NULL) {
                //trace_extra_point_start(4 + 5);
                ret = udp_sendto(socket->udp_pcb, p, &msg->src_addr, msg->src_port);
                //trace_extra_point_end(4 + 5, 1);
            } else {
                error = ERR_MEM;
            }
            //trace_extra_point_end(6, 1);
        } else {
            //ret = tcp_write(socket->tcp_pcb, msg->buf + msg->done_len,
                            //msg->total_len - msg->done_len, TCP_WRITE_FLAG_COPY);
        }

        //trace_extra_point_start(7);
        if (p != NULL) {
            //trace_extra_point_start(4 + 18);
            pbuf_free(p);
            //trace_extra_point_end(4 + 18, 1);
        }

        if (ret != ERR_OK) {
            /*  Free the internal tx buffer in case tx fails. Up to the client to retry the trasmission */
            ZF_LOGE("tx main: This shouldn't happen.  Handle error case: %d", ret);
            msg->done_len = -1;
            tx_complete((void*)(uintptr_t)handle.first, 0);
            continue;
        }

        msg->done_len = msg->total_len;
        tx_complete((void*)(uintptr_t)handle.first, msg->total_len);
        //trace_extra_point_end(7, 1);
    }
    //trace_extra_point_end(3, 1);
    //trace_extra_point_end(4 + 1, 1);
}

static void rx_complete(void *cookie, int len)
{
    //trace_extra_point_start(4 + 14);
    virtqueue_ring_object_t handle;
    handle.first = (uint32_t)(uintptr_t)cookie;
    handle.cur = (uint32_t)(uintptr_t)cookie;
    if (!virtqueue_add_used_buf(&rx_virtqueue, &handle, len)) {
        ZF_LOGE("RX: Error while enqueuing available buffer");

    }
    emit_client_async = 1;
    //trace_extra_point_end(4 + 14, 1);
}

static int move_packet_to_msg(tx_msg_t *msg)
{
    pbuf_chain_t *curr_pbuf = socket_array[msg->socket_fd].pbufs;

    if (curr_pbuf == NULL) {
        return 0;
    }

    int total_bytes = curr_pbuf->p->tot_len;

    msg->src_addr = curr_pbuf->ip_addr;
    msg->src_port = curr_pbuf->port;
    msg->buf_ref = curr_pbuf->p->payload;

    pop_pbuf_from_chain(&socket_array[msg->socket_fd]);

    return total_bytes;
}

static void rx_socket(lwipserver_socket_t *socket)
{
    //trace_extra_point_start(4 + 4);
    assert(socket != NULL);

    if (socket->async_socket == NULL) {
       ZF_LOGE("Socket isn't setup for async");
       return;
    }

    while (socket->async_socket->rx_pending_queue) {
        ZF_LOGF_IF(socket->async_socket->rx_pending_queue_end == NULL,
                   "Inconsistent queue state");
        int bytes_read;
        tx_msg_t *msg = socket->async_socket->rx_pending_queue;

        if (socket->proto == UDP) {
            //trace_extra_point_start(4 + 16);
            bytes_read = move_packet_to_msg(msg);
            //bytes_read = copy_udp_socket_packets(msg->socket_fd, msg->buf + msg->done_len,
                                                 //msg->total_len, &msg->src_addr,
                                                 //&msg->src_port);
            //trace_extra_point_end(4 + 16, 1);
        } else {
            //bytes_read = copy_tcp_socket_packets(msg->socket_fd, msg->buf + msg->done_len,
                                                 //msg->total_len - msg->done_len);
        }

        if ((socket->proto == TCP && bytes_read < (msg->total_len-msg->done_len)) ||
            (socket->proto == UDP && bytes_read == 0)) {
            msg->done_len += bytes_read;
            //trace_extra_point_end(4 + 4, 1);
            return;
        } else {
            msg->done_len += bytes_read;
            socket->async_socket->rx_pending_queue = msg->next;
            if (socket->async_socket->rx_pending_queue_end == msg) {
                socket->async_socket->rx_pending_queue_end = NULL;
            }
            rx_complete(msg->cookie_save, msg->total_len);
        }
    }
    //trace_extra_point_end(4 + 4, 1);
}

static void rx_queue_handle(void)
{
    int error;

    //trace_extra_point_start(4 + 3);
    while(1) {
        virtqueue_ring_object_t handle;

        if (virtqueue_get_available_buf(&rx_virtqueue, &handle) == 0) {
            break;
        }

        uint64_t buf;
        unsigned len;
        vq_flags_t flag;
        int more = virtqueue_gather_available(&rx_virtqueue, &handle, &buf, &len, &flag);
        if (more == 0) {
            ZF_LOGE("No message received");
            break;
        }

        tx_msg_t *msg = camkes_virtqueue_device_offset_to_buffer(&rx_virtqueue, buf);
        ZF_LOGF_IF(msg == NULL, "msg is null");
        ZF_LOGF_IF((msg->total_len > 1400) || (msg->total_len == 0), "bad msg len in rx %zd", msg->total_len);

        error = server_check_common(msg->socket_fd);
        if (error) {
            ZF_LOGE("Socket is null");
            msg->done_len = -1;
            rx_complete((void *) (uintptr_t) handle.first, 0);
        }

        lwipserver_socket_t *socket = &socket_array[msg->socket_fd];

        if (socket->async_socket == NULL) {
            ZF_LOGE("Socket isn't setup for async");
            msg->done_len = -1;
            rx_complete((void*)(uintptr_t)handle.first, 0);
            continue;
        }

        if (socket->async_socket->rx_pending_queue) {
            ZF_LOGF_IF(socket->async_socket->rx_pending_queue_end == NULL,
                       "Inconsistent queue state");
            socket->async_socket->rx_pending_queue_end->next = msg;
            socket->async_socket->rx_pending_queue_end = msg;
            msg->next = NULL;
            msg->cookie_save = (void*)(uintptr_t)handle.first;
            continue;
        }

        int bytes_read;
        if (socket->proto == UDP) {
            //trace_extra_point_start(4 + 6);
            bytes_read = move_packet_to_msg(msg);
            //bytes_read = copy_udp_socket_packets(msg->socket_fd, msg->buf + msg->done_len,
                                                 //msg->total_len - msg->done_len,
                                                 //&msg->src_addr, &msg->src_port);
            //trace_extra_point_end(4 + 6, 1);
        } else {
            //bytes_read = copy_tcp_socket_packets(msg->socket_fd, msg->buf + msg->done_len,
                                                 //msg->total_len - msg->done_len);
        }

        if ((socket->proto == TCP && bytes_read < msg->total_len) ||
            (socket->proto == UDP && bytes_read == 0)) {
            msg->done_len = bytes_read;
            msg->cookie_save = (void*)(uintptr_t)handle.first;
            msg->next = NULL;
            socket->async_socket->rx_pending_queue = msg;
            socket->async_socket->rx_pending_queue_end = msg;
            //trace_extra_point_end(4 + 3, 1);
            return;
        } else {
            msg->done_len = bytes_read;
            rx_complete((void*)(uintptr_t)handle.first, msg->done_len);
        }
    }
    //trace_extra_point_end(4 + 3, 1);
}

static void tx_queue_handle_irq(seL4_Word badge, void *cookie)
{
    //trace_extra_point_start(2);
    //trace_extra_point_start(0);
    rx_queue_handle();
    //trace_extra_point_end(0, 1);
    //trace_extra_point_start(1);
    tx_queue_handle();
    //trace_extra_point_end(1, 1);
    //trace_extra_point_end(2, 1);
}

static err_t lwipserver_sent_callback(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    //trace_extra_point_start(4 + 20);
    assert(arg);

    lwipserver_socket_t *socket = arg;

    if (socket->async_socket != NULL) {
        //trace_extra_point_start(4 + 21);
        tx_queue_handle();
        //trace_extra_point_end(4 + 21, 1);
        //trace_extra_point_start(4 + 22);
        tx_socket(socket);
        //trace_extra_point_end(4 + 22, 1);
    }

    //trace_extra_point_end(4 + 20, 1);
    return ERR_OK;
}

typedef struct lwip_custom_pbuf {
    struct pbuf_custom p;
    bool is_echo;
    void *dma_buf;
} lwip_custom_pbuf_t;

static int add_pbuf_to_chain(lwipserver_socket_t *socket, struct pbuf *p,
                             const ip_addr_t *ip_addr, u16_t port)
{
    pbuf_chain_t *new_node = NULL;
    int error = ps_calloc(malloc_ops, 1, sizeof(*new_node), (void **) &new_node);
    if (error) {
        ZF_LOGE("Failed to allocate memory for the pbuf new_node head");
        return error;
    }

    if (p->flags & PBUF_FLAG_IS_CUSTOM) {
        lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) p;
        custom_pbuf->is_echo = true;
    }

    new_node->p = p;
    if (ip_addr != NULL) {
        new_node->ip_addr = (ip_addr_t) * ip_addr;
    }
    new_node->port = port;

    if (socket->pbuf_tail) {
        socket->pbuf_tail->next = new_node;
        socket->pbuf_tail = new_node;
    } else {
        socket->pbuf_tail = new_node;
        socket->pbufs = new_node;
    }

    return 0;
}

static void lwipserver_udp_receive_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                                            const ip_addr_t *addr, u16_t port)
{
    //trace_extra_point_start(4 + 7);
    assert(arg);

    lwipserver_socket_t *socket = arg;

    //trace_extra_point_start(4 + 8);
    add_pbuf_to_chain(socket, p, addr, port);
    //trace_extra_point_end(4 + 8, 1);

    if (socket->async_socket != NULL) {
        //trace_extra_point_start(4 + 9);
        rx_queue_handle();
        //trace_extra_point_end(4 + 9, 1);
        //trace_extra_point_start(4 + 10);
        rx_socket(socket);
        //trace_extra_point_end(4 + 10, 1);
    } else {
        socket->outstanding_events |= LWIPSERVER_DATA_AVAIL;
        emit_client = 1;
    }
    //trace_extra_point_end(4 + 7, 1);
}

static err_t lwipserver_tcp_receive_callback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
                                             err_t err)
{
    assert(arg);

    lwipserver_socket_t *socket = arg;

    if (p == NULL) {
        socket->outstanding_events |= LWIPSERVER_PEER_CLOSED;
        emit_client = 1;
        return ERR_OK;
    }

    if (err != ERR_OK) {
        ZF_LOGE("Encountered error %hhd when trying to receive TCP packet", err);
        return ERR_OK;
    }

    int error = add_pbuf_to_chain(socket, p, NULL, 0);
    ZF_LOGF_IF(error, "Failed to chain a pbuf for reading later");
    tcp_recved(socket->tcp_pcb, p->tot_len);

    if (socket->async_socket != NULL) {
        rx_queue_handle();
        rx_socket(socket);
    } else {
        socket->outstanding_events |= LWIPSERVER_DATA_AVAIL;
        emit_client = 1;
    }

    return ERR_OK;
}

int lwip_control_open(bool is_udp)
{
    int free_socket_id = find_next_socket_id();
    if (free_socket_id == -1) {
        ZF_LOGE("Can't open a socket as there is no more space left");
        return -ENOSPC;
    }

    assert(!socket_array[free_socket_id].in_use);
    if (is_udp) {
        socket_array[free_socket_id].udp_pcb = udp_new_ip_type(IPADDR_TYPE_V4);
        if (socket_array[free_socket_id].udp_pcb == NULL) {
            ZF_LOGE("Failed to open a new UDP socket");
            return -EIO;
        }
        socket_array[free_socket_id].proto = UDP;
        /* Set up the receive callback for when the this 'socket' receives any packets */
        udp_recv(socket_array[free_socket_id].udp_pcb, lwipserver_udp_receive_callback,
                 &socket_array[free_socket_id]);
    } else {
        socket_array[free_socket_id].tcp_pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
        if (socket_array[free_socket_id].tcp_pcb == NULL) {
            ZF_LOGE("Failed to open a new TCP socket");
            return -EIO;
        }
        socket_array[free_socket_id].proto = TCP;
        /* Set up the receive callback for when the this 'socket' receives any packets */
        tcp_arg(socket_array[free_socket_id].tcp_pcb, &socket_array[free_socket_id]);
        tcp_sent(socket_array[free_socket_id].tcp_pcb, lwipserver_sent_callback);
        tcp_recv(socket_array[free_socket_id].tcp_pcb, lwipserver_tcp_receive_callback);
    }

    socket_array[free_socket_id].in_use = true;
    socket_array[free_socket_id].socket_fd = free_socket_id;
    socket_array[free_socket_id].client_id = lwip_control_get_sender_id();

    return free_socket_id;
}

int lwip_control_bind(int socket_fd, ip_addr_t local_addr, uint16_t port)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    err_t error;

    if (socket_array[socket_fd].proto == TCP) {
        error = tcp_bind(socket_array[socket_fd].tcp_pcb, &local_addr, port);
    } else {
        error = udp_bind(socket_array[socket_fd].udp_pcb, &local_addr, port);
    }

    return (error == ERR_OK) ? 0 : error;
}

static err_t lwipserver_connect_callback(void *arg, struct tcp_pcb *pcb, err_t err)
{
    assert(arg);
    lwipserver_socket_t *socket = arg;
    socket->outstanding_events |= LWIPSERVER_CONNECTED;
    emit_client = 1;
    return ERR_OK;
}

int lwip_control_connect(int socket_fd, ip_addr_t server_addr, uint16_t port)
{

    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    err_t error;

    if (socket_array[socket_fd].proto == UDP) {
        error = udp_connect(socket_array[socket_fd].udp_pcb, &server_addr, port);
    } else {
        error = tcp_connect(socket_array[socket_fd].tcp_pcb, &server_addr, port,
                            lwipserver_connect_callback);
    }

    return (error == ERR_OK) ? 0 : error;
}

static err_t lwipserver_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    assert(arg);

    lwipserver_socket_t *socket = arg;

    if (err != ERR_OK) {
        // NOTE Is this the proper return code to return on error?
        return ERR_OK;
    }

    if (pending_num == LWIPSERVER_MAX_PENDING) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    tcp_backlog_delayed(newpcb);

    pending_connections[pending_tail] = newpcb;
    pending_tail = (pending_tail + 1) % LWIPSERVER_MAX_PENDING;
    pending_num++;

    socket->outstanding_events |= LWIPSERVER_PEER_AVAIL;
    emit_client = 1;

    return ERR_OK;
}

int lwip_control_listen(int socket_fd, int backlog)
{

    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    if (backlog > LWIPSERVER_MAX_PENDING) {
        return -EINVAL;
    }

    if (socket_array[socket_fd].proto == UDP) {
        return -EINVAL;
    }

    err_t error = ERR_OK;
    struct tcp_pcb *new_pcb = NULL;

    new_pcb = tcp_listen_with_backlog_and_err(socket_array[socket_fd].tcp_pcb, backlog,
                                              &error);
    if (new_pcb == NULL) {
        return error;
    }

    socket_array[socket_fd].tcp_pcb = new_pcb;

    tcp_accept(socket_array[socket_fd].tcp_pcb, lwipserver_accept_callback);

    return 0;
}

int lwip_control_accept(int socket_fd, ip_addr_t *peer_addr, uint16_t *peer_port, int *peer_fd)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    if (socket_array[socket_fd].proto == UDP) {
        return -EINVAL;
    }

    if (pending_num == 0) {
        return -ENOENT;
    }

    int free_id = find_next_socket_id();
    if (free_id == -1) {
        ZF_LOGE("No sockets left to accept a new connection");
        return -ENOSPC;
    }

    tcp_backlog_accepted(pending_connections[pending_head]);

    socket_array[free_id].in_use = true;
    socket_array[free_id].tcp_pcb = pending_connections[pending_head];
    socket_array[free_id].proto = TCP;
    socket_array[free_id].client_id = lwip_control_get_sender_id();

    *peer_addr = socket_array[free_id].tcp_pcb->remote_ip;
    *peer_port = socket_array[free_id].tcp_pcb->remote_port;
    *peer_fd = free_id;

    pending_connections[pending_head] = NULL;
    pending_num--;
    pending_head = (pending_head + 1) % LWIPSERVER_MAX_PENDING;

    tcp_arg(socket_array[free_id].tcp_pcb, &socket_array[free_id]);
    tcp_recv(socket_array[free_id].tcp_pcb, lwipserver_tcp_receive_callback);
    tcp_sent(socket_array[free_id].tcp_pcb, lwipserver_sent_callback);

    return 0;
}

int lwip_control_shutdown(int socket_fd, int shut_rx, int shut_tx)
{

    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    if (socket_array[socket_fd].proto == UDP) {
        return -EINVAL;
    }

    err_t error = tcp_shutdown(socket_array[socket_fd].tcp_pcb, shut_rx, shut_tx);

    if (error == ERR_OK) {
        if (shut_rx && shut_tx) {
            socket_array[socket_fd].in_use = false;
            socket_array[socket_fd].tcp_pcb = NULL;
        }
    }

    return (error == ERR_OK) ? 0 : error;
}

static void destroy_pbuf_chain(lwipserver_socket_t *socket)
{
    pbuf_chain_t *curr = socket->pbufs;
    pbuf_chain_t *prev = NULL;
    while (curr != NULL) {
        prev = curr;
        curr = curr->next;
        pbuf_free(prev->p);
        ZF_LOGF_IF(ps_free(malloc_ops, sizeof(*prev), prev),
                   "Failed to free a pbuf_chain_t node");
    }
}

static void cleanup_async_socket(lwipserver_socket_t *socket)
{
    tx_msg_t *msg;
    /* Drain the virtqueues and move them back into the used ring */
    while (socket->async_socket->tx_pending_queue) {
        ZF_LOGF_IF(socket->async_socket->tx_pending_queue_end == NULL,
                   "Inconsistent queue state");
        msg = socket->async_socket->tx_pending_queue;
        msg->done_len = -1;
        socket->async_socket->tx_pending_queue = msg->next;
        if (socket->async_socket->tx_pending_queue_end == msg) {
            socket->async_socket->tx_pending_queue_end = NULL;

        }
        tx_complete(msg->cookie_save, 0);
    }
    while (socket->async_socket->rx_pending_queue) {
        ZF_LOGF_IF(socket->async_socket->rx_pending_queue_end == NULL,
                   "Inconsistent queue state");
        msg = socket->async_socket->rx_pending_queue;
        msg->done_len = -1;
        socket->async_socket->rx_pending_queue = msg->next;
        if (socket->async_socket->rx_pending_queue_end == msg) {
            socket->async_socket->rx_pending_queue_end = NULL;

        }
        rx_complete(msg->cookie_save, 0);
    }

    ps_free(malloc_ops, sizeof(lwipserver_socket_async_t), socket->async_socket);
    socket->async_socket = NULL;
}

int lwip_control_close(int socket_fd)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    err_t error = ERR_OK;
    if (socket_array[socket_fd].proto == UDP) {
        udp_remove(socket_array[socket_fd].udp_pcb);
        socket_array[socket_fd].udp_pcb = NULL;
    } else {
        error = tcp_close(socket_array[socket_fd].tcp_pcb);
        if (error == ERR_OK) {
            socket_array[socket_fd].tcp_pcb = NULL;
        }
    }

    if (error == ERR_OK) {
        socket_array[socket_fd].in_use = false;
        socket_array[socket_fd].outstanding_events = 0;
        destroy_pbuf_chain(&socket_array[socket_fd]);
        socket_array[socket_fd].pbuf_tail = NULL;
        socket_array[socket_fd].pbufs = NULL;
        socket_array[socket_fd].client_id = 0;
        if (socket_array[socket_fd].async_socket != NULL) {
            cleanup_async_socket(&socket_array[socket_fd]);
        }
    }

    return (error == ERR_OK) ? 0 : error;
}

int lwip_control_poll_events(int socket_fd)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    bool sent_message = false;

    if (socket_array[socket_fd].outstanding_events) {
        lwipserver_event_t event = { .type = socket_array[socket_fd].outstanding_events,
                                     .socket_fd = socket_fd };
        if (event.type & LWIPSERVER_PEER_CLOSED) {
            /* Eliminate this race condition where the socket may
             * have been closed before the user can read the data */
            event.type &= ~(LWIPSERVER_DATA_AVAIL);
        }
        int error = camkes_msgqueue_send(&event_sender, &event, sizeof(event));
        ZF_LOGF_IF(error, "Failed to enqueue message onto the message queue");
        socket_array[socket_fd].outstanding_events = 0;
        sent_message = true;
    }

    return (sent_message == true) ? 1 : 0;
}

int lwip_control_set_async(int socket_fd, bool enable)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    lwipserver_socket_t *socket = &socket_array[socket_fd];

    int error = 0;
    if (enable && (socket->async_socket == NULL)) {
        error = ps_calloc(malloc_ops, 1, sizeof(lwipserver_socket_async_t),
                          (void **) &socket->async_socket);
        if (error) {
            ZF_LOGE("Failed to allocate memory for the async socket");
            return -ENOMEM;
        }
    } else if (!enable && (socket->async_socket != NULL)) {
        cleanup_async_socket(socket);
    }

    return 0;
}

seL4_Word lwip_send_get_sender_id(void);
size_t lwip_send_buf_size(seL4_Word);
void *lwip_send_buf(seL4_Word);
seL4_Word lwip_send_enumerate_badge(unsigned int);

int lwip_send_write(int socket_fd, int len, int buffer_offset)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    if (socket_array[socket_fd].proto == UDP) {
        return -EINVAL;
    }

    seL4_Word client_badge = lwip_send_get_sender_id();
    size_t buffer_size = lwip_send_buf_size(lwip_send_enumerate_badge(client_badge));
    void *client_buf = lwip_send_buf(lwip_send_enumerate_badge(client_badge));

    if (buffer_offset + len > buffer_size) {
        return -EINVAL;
    }

    u16_t avail_send_size = tcp_sndbuf(socket_array[socket_fd].tcp_pcb);
    len = MIN(avail_send_size, (unsigned) len);
    if (len == 0) {
        return 0;
    }

    // TODO Investigate zero-copy ways of this API
    err_t error = tcp_write(socket_array[socket_fd].tcp_pcb, client_buf + buffer_offset,
                            len, TCP_WRITE_FLAG_COPY);
    if (error == ERR_MEM) {
        len = 0;
        error = ERR_OK;
    }

    return (error == ERR_OK) ? len : error;
}

int lwip_send_send(int socket_fd, int len, int buffer_offset)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    if (socket_array[socket_fd].proto == TCP) {
        return -EINVAL;
    }

    seL4_Word client_badge = lwip_send_get_sender_id();
    size_t buffer_size = lwip_send_buf_size(lwip_send_enumerate_badge(client_badge));
    void *client_buf = lwip_send_buf(lwip_send_enumerate_badge(client_badge));

    if (buffer_offset + len > buffer_size) {
        return -EINVAL;
    }

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_POOL);
    if (p == NULL) {
        return -ENOMEM;
    }

    err_t error = pbuf_take(p, client_buf + buffer_offset, len);

    if (error != ERR_OK) {
        pbuf_free(p);
    }

    error = udp_send(socket_array[socket_fd].udp_pcb, p);
    if (error == ERR_MEM) {
        len = 0;
        error = ERR_OK;
    }

    pbuf_free(p);

    return (error == ERR_OK) ? len : error;
}

int lwip_send_sendto(int socket_fd, int len, int buffer_offset, ip_addr_t dst_addr,
                     u16_t remote_port)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    if (socket_array[socket_fd].proto == TCP) {
        return -EINVAL;
    }

    seL4_Word client_badge = lwip_send_get_sender_id();
    size_t buffer_size = lwip_send_buf_size(lwip_send_enumerate_badge(client_badge));
    void *client_buf = lwip_send_buf(lwip_send_enumerate_badge(client_badge));

    if (buffer_offset + len > buffer_size) {
        return -EINVAL;
    }

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_POOL);

    if (p == NULL) {
        return -ENOMEM;
    }

    err_t error = pbuf_take(p, client_buf + buffer_offset, len);

    if (error != ERR_OK) {
        pbuf_free(p);
    }

    error = udp_sendto(socket_array[socket_fd].udp_pcb, p, &dst_addr, remote_port);
    if (error == ERR_MEM) {
        len = 0;
        error = ERR_OK;
    }

    pbuf_free(p);

    return (error == ERR_OK) ? len : error;
}

seL4_Word lwip_recv_get_sender_id(void);
size_t lwip_recv_buf_size(seL4_Word);
void *lwip_recv_buf(seL4_Word);
seL4_Word lwip_recv_enumerate_badge(unsigned int);

int lwip_recv_read(int socket_fd, int len, int buffer_offset)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    if (socket_array[socket_fd].proto == UDP) {
        return -EINVAL;
    }

    seL4_Word client_badge = lwip_recv_get_sender_id();
    size_t buffer_size = lwip_recv_buf_size(lwip_recv_enumerate_badge(client_badge));
    void *client_buf = lwip_recv_buf(lwip_recv_enumerate_badge(client_badge));

    if (buffer_offset + len > buffer_size) {
        return -EINVAL;
    }

    int bytes_read = copy_tcp_socket_packets(socket_fd, client_buf + buffer_offset, len);

    return bytes_read;
}

int lwip_recv_recv(int socket_fd, int len, int buffer_offset)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    if (socket_array[socket_fd].proto == TCP) {
        return -EINVAL;
    }

    seL4_Word client_badge = lwip_recv_get_sender_id();
    size_t buffer_size = lwip_recv_buf_size(lwip_recv_enumerate_badge(client_badge));
    void *client_buf = lwip_recv_buf(lwip_recv_enumerate_badge(client_badge));

    if (buffer_offset + len > buffer_size) {
        return -EINVAL;
    }

    return copy_udp_socket_packets(socket_fd, client_buf + buffer_offset, len, NULL, NULL);
}

int lwip_recv_recvfrom(int socket_fd, int len, int buffer_offset, ip_addr_t *src_addr,
                       u16_t *remote_port)
{
    int check_result = server_check_common(socket_fd);
    if (check_result) {
        return check_result;
    }

    if (socket_array[socket_fd].proto == TCP) {
        return -EINVAL;
    }

    seL4_Word client_badge = lwip_recv_get_sender_id();
    size_t buffer_size = lwip_recv_buf_size(lwip_recv_enumerate_badge(client_badge));
    void *client_buf = lwip_recv_buf(lwip_recv_enumerate_badge(client_badge));

    if (buffer_offset + len > buffer_size) {
        return -EINVAL;
    }

    return copy_udp_socket_packets(socket_fd, client_buf + buffer_offset, len, src_addr, remote_port);
}

static void notify_client(UNUSED seL4_Word badge, void *cookie)
{
    /* TODO This is a hack, and only assumes one client, fix this so that it is
     * aware of multiple clients */
    if (emit_client) {
        lwip_control_emit(1);
        emit_client = 0;
    }
    if (emit_client_async) {
        tx_virtqueue.notify();
        emit_client_async = 0;
    }
}

int lwip_socket_sync_server_init_late(ps_io_ops_t *io_ops, register_callback_handler_fn_t callback_handler)
{
    callback_handler(0, "lwip_notify_client", notify_client, NULL);

    int error = trace_extra_point_register_name(0, "inet_pseudo_chksum");
    ZF_LOGF_IF(error, "Failed to register extra trace point 0");

    /*
    int error = trace_extra_point_register_name(0, "rx_queue_handle_in_handler");
    ZF_LOGF_IF(error, "Failed to register extra trace point 0");

    error = trace_extra_point_register_name(1, "tx_queue_handle_in_handler");
    ZF_LOGF_IF(error, "Failed to register extra trace point 1");

    error = trace_extra_point_register_name(2, "tx_queue_handle_irq");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 2);

    error = trace_extra_point_register_name(3, "tx_queue_handle");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 3);

    error = trace_extra_point_register_name(4, "virtqueue_prologue");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4);

    error = trace_extra_point_register_name(5, "tx_checks");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 5);

    error = trace_extra_point_register_name(6, "udp_tx");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 6);

    error = trace_extra_point_register_name(7, "send_cleanup");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 7);
    */

    /*
    error = trace_extra_point_register_name(4 + 2, "tx_socket");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 2);

    error = trace_extra_point_register_name(4 + 3, "rx_queue_handle");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 3);

    error = trace_extra_point_register_name(4 + 4, "rx_socket");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 4);

    error = trace_extra_point_register_name(4 + 5, "udp_sendto");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 5);

    error = trace_extra_point_register_name(4 + 6, "move_packet_in_queue");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 6);

    error = trace_extra_point_register_name(4 + 7, "udp_receive_callback");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 7);

    error = trace_extra_point_register_name(4 + 8, "add_pbuf_to_chain");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 8);

    error = trace_extra_point_register_name(4 + 9, "rx_queue_handle_in_cb");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 9);

    error = trace_extra_point_register_name(4 + 10, "rx_socket_in_cb");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 10);

    error = trace_extra_point_register_name(4 + 11, "pbuf_copy_partial");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 11);

    error = trace_extra_point_register_name(4 + 12, "pbuf_take_in_queue");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 12);

    error = trace_extra_point_register_name(4 + 13, "pbuf_free_in_pop");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 13);

    error = trace_extra_point_register_name(4 + 14, "rx_complete");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 14);

    error = trace_extra_point_register_name(4 + 15, "tx_complete");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 15);

    error = trace_extra_point_register_name(4 + 16, "move_packet_in_socket");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 16);

    error = trace_extra_point_register_name(4 + 17, "pbuf_take_in_socket");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 17);

    error = trace_extra_point_register_name(4 + 18, "pbuf_free_in_tx_queue");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 18);

    error = trace_extra_point_register_name(4 + 19, "pbuf_free_in_tx_socket");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 19);

    error = trace_extra_point_register_name(4 + 20, "lwip_sent_callback");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 20);

    error = trace_extra_point_register_name(4 + 21, "tx_queue_handle_in_cb");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 21);

    error = trace_extra_point_register_name(4 + 22, "tx_socket_in_cb");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 22);

    error = trace_extra_point_register_name(4 + 23, "pbuf_alloc_in_queue");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 23);

    error = trace_extra_point_register_name(4 + 24, "pbuf_alloc_in_socket");
    ZF_LOGF_IF(error, "Failed to register extra trace point %d", 4 + 24);
    */

    return 0;
}

int lwip_socket_sync_server_init(ps_io_ops_t *io_ops, register_callback_handler_fn_t callback_handler)
{
    malloc_ops = &io_ops->malloc_ops;

    seL4_Word tx_badge;
    seL4_Word rx_badge;

    int error = camkes_virtqueue_device_init_with_recv(&tx_virtqueue,
                                                       camkes_virtqueue_get_id_from_name("lwip_tx"),
                                                       NULL, &tx_badge);
    ZF_LOGF_IF(error, "Failed to initialise the TX virtqueue for lwipserver");

    error = camkes_virtqueue_device_init_with_recv(&rx_virtqueue,
                                                   camkes_virtqueue_get_id_from_name("lwip_rx"),
                                                   NULL, &rx_badge);
    ZF_LOGF_IF(error, "Failed to initialise the RX virtqueue for lwipserver");

    error = camkes_msgqueue_sender_init(0, &event_sender);
    ZF_LOGF_IF(error, "Failed to init sender side of the msgqueue");

    error = callback_handler(tx_badge, "client_event_handler",
                             tx_queue_handle_irq, NULL);
    ZF_LOGF_IF(error, "Failed to register the handler");

    return 0;
}
