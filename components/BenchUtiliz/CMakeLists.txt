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

project(BenchUtiliz C)

DeclareCAmkESComponent(BenchUtiliz SOURCES src/benchUtiliz.c LIBS sel4bench)
CAmkESAddImportPath(camkes-include)
CAmkESAddCPPInclude(camkes-include)

add_library(BenchUtiliz-profile EXCLUDE_FROM_ALL ${CMAKE_CURRENT_LIST_DIR}/src/dump_profile.c)
target_link_libraries(BenchUtiliz-profile sel4prof platsupport)
# Force the benchutilz_setup_profile_dump constructor to be included in dependants
target_link_options(BenchUtiliz-profile BEFORE INTERFACE "-Wl,-ubenchutilz_setup_profile_dump")

if(KernelArchARM)
    set(KernelArmExportPMUUser ON CACHE BOOL "" FORCE)
elseif(KernelArchX86)
    set(KernelExportPMCUser ON CACHE BOOL "" FORCE)
else()
    message("Unsupported platform.")
endif()
