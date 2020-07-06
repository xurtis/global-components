#
# Copyright 2020, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the BSD 2-Clause license. Note that NO WARRANTY is provided.
# See "LICENSE_BSD2.txt" for details.
#
# @TAG(DATA61_BSD)
#

cmake_minimum_required(VERSION 3.8.2)

project(lwip-socket-sync-package C)

CAmkESAddImportPath(camkes-include)
CAmkESAddCPPInclude(camkes-include)
CAmkESAddTemplatesPath(templates)

DeclareCAmkESConnector(
    LwipSocketSyncServerInit
    FROM
    lwip-socket-sync-server-init.template.c
    FROM_LIBS
    lwip-socket-sync-server
    TO
    empty.c
)

DeclareCAmkESConnector(LwipSocketSyncClientInit FROM empty.c FROM_LIBS LWIPServer-client TO empty.c)

add_library(lwip-socket-sync INTERFACE)
target_include_directories(lwip-socket-sync INTERFACE include)

add_library(LWIPServer-client INTERFACE)
target_include_directories(LWIPServer-client INTERFACE client_include)
target_link_libraries(LWIPServer-client INTERFACE lwip-socket-sync)

add_library(lwip-socket-sync-server EXCLUDE_FROM_ALL server/server.c)
target_link_libraries(lwip-socket-sync-server sel4camkes lwip lwip-socket-sync LWIPServer-client)
