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

#define _VAR_STRINGIZE(...) #__VA_ARGS__
#define VAR_STRINGIZE(...) _VAR_STRINGIZE(__VA_ARGS__)

import <lwip-socket-sync.camkes>;

#define lwip_socket_sync_client_interfaces(name) \
    dataport lwipserver_event_t name##_events; \
    uses LWIPControl name##_control; \
    uses LWIPRecv name##_recv; \
    uses LWIPSend name##_send; \
    emits Init name##_init1; \
    consumes Init name##_init2; \
    uses VirtQueueDrv name##_tx; \
    uses VirtQueueDrv name##_rx; \
    dataport Buf name##_dma_pool;

#define lwip_socket_sync_server_interfaces(name) \
    dataport lwipserver_event_t name##_events; \
    provides LWIPControl name##_control; \
    provides LWIPRecv name##_recv; \
    provides LWIPSend name##_send; \
    emits Init name##_init1; \
    consumes Init name##_init2; \
    uses VirtQueueDev name##_tx; \
    uses VirtQueueDev name##_rx; \
    attribute int name##_tx_shmem_size = 8192 * 16;  \
    attribute int name##_rx_shmem_size = 8192 * 16;  \
    dataport Buf name##_dma_pool;

#define lwip_socket_sync_server_connections(name) \
    connection LwipSocketSyncServerInit name##_server_init(from name##_init1, to name##_init2);

#define lwip_socket_sync_client_connections(client, client_name, server, server_name) \
    connection seL4PicoServerSignal client##_##client_name##server##_##server_name##_control(from client.client_name##_control, to server.server_name##_control); \
    connection seL4PicoServer client##_##client_name##server##_##server_name##_recv(from client.client_name##_recv, to server.server_name##_recv); \
    connection seL4PicoServer client##_##client_name##server##_##server_name##_send(from client.client_name##_send, to server.server_name##_send); \
    connection LwipSocketSyncClientInit client##_##client_name##_client_init(from client.client_name##_init1, to client.client_name##_init2); \
    connection seL4MessageQueue client##_##client_name##server##_##server_name##_msgqueue(from server.server_name##_events, to client.client_name##_events); \
    component VirtQueueInit client_name##d0;                            \
    component VirtQueueInit client_name##d1;                            \
    connection seL4VirtQueues client_name##_virtq_conn0(to client_name##d0.init, from client.client_name##_tx, from server.server_name##_tx); \
    connection seL4VirtQueues client_name##_virtq_conn1(to client_name##d1.init, from client.client_name##_rx, from server.server_name##_rx); \
    connection seL4DMASharedData client_name##_dma(from client.client_name##_dma_pool, to server.server_name##_dma_pool);

#define lwip_socket_sync_server_configurations(name) \
    name##_server_init.connection_name = VAR_STRINGIZE(name); \

#define lwip_socket_sync_client_configurations(client, client_name, packet_size, q_length, async_pool_size) \
    client.client_name##_recv_shmem_size = packet_size; \
    client.client_name##_send_shmem_size = packet_size; \
    client##_##client_name##_client_init.connection_name = VAR_STRINGIZE(client_name); \
    client_name##_dma.size = async_pool_size; \
    client_name##_virtq_conn0.queue_length = q_length; \
    client_name##_virtq_conn1.queue_length = q_length; \
    client.client_name##_tx_shmem_size = 8192 * 16;     \
    client.client_name##_rx_shmem_size = 8192 * 16;     \
    client_name##_dma.controller = VAR_STRINGIZE(client.client_name##_dma_pool);

#define lwip_socket_msgqueue_configurations(client, client_name, server, server_name) \
    server.server_name##_events_id = 0; \
    client.client_name##_events_id = 0; \
    client##_##client_name##server##_##server_name##_msgqueue.queue_size = 128; \
    client##_##client_name##server##_##server_name##_msgqueue.size = 8192;
