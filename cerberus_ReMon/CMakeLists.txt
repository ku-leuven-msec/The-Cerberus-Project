cmake_minimum_required(VERSION 3.17)
project(ReMon)

set(CMAKE_CXX_STANDARD 14)

include_directories(MVEE/Inc)
include_directories(MVEE/Inc/arch)
include_directories(MVEE/Inc/arch/amd64)
include_directories(MVEE/Inc/backends)
include_directories(MVEE/Inc/backends/ptrace)
include_directories(MVEE_LD_Loader/amd64)

add_executable(ReMon
        MVEE/Inc/arch/amd64/MVEE_private_arch.h
        MVEE/Inc/arch/amd64/MVEE_syscall_alias_locks.h
        MVEE/Inc/arch/amd64/MVEE_syscall_handler_prototypes.h
        MVEE/Inc/arch/amd64/MVEE_syscall_handler_table.h
        MVEE/Inc/arch/amd64/MVEE_syscall_string_table.h
        MVEE/Inc/backends/ptrace/MVEE_ptrace.h
        MVEE/Inc/MVEE.h
        MVEE/Inc/MVEE_build_config.h
        MVEE/Inc/MVEE_erim.h
        MVEE/Inc/MVEE_erim_api_inlined.h
        MVEE/Inc/MVEE_exceptions.h
        MVEE/Inc/MVEE_fake_syscall.h
        MVEE/Inc/MVEE_interaction.h
        MVEE/Inc/MVEE_logging.h
        MVEE/Inc/MVEE_macros.h
        MVEE/Inc/MVEE_memory.h
        MVEE/Inc/MVEE_mman.h
        MVEE/Inc/MVEE_monitor.h
        MVEE/Inc/MVEE_numcalls.h
        MVEE/Inc/MVEE_pkeys.h
        MVEE/Inc/MVEE_signals.h
        MVEE/Inc/MVEE_syscalls.h
        MVEE/Src/MVEE.cpp
        MVEE/Src/MVEE_config.cpp
        MVEE/Src/MVEE_logging.cpp
        MVEE/Src/MVEE_logging_strings.cpp
        MVEE/Src/MVEE_memory.cpp
        MVEE/Src/MVEE_mman.cpp
        MVEE/Src/MVEE_monitor.cpp
        MVEE/Src/MVEE_signals.cpp
        MVEE/Src/MVEE_syscalls.cpp
        MVEE/Src/MVEE_Cerberus_support.cpp
        MVEE/Src/MVEE_syscalls_handlers.cpp
        MVEE/Src/MVEE_syscalls_support.cpp
        MVEE/Src/MVEE_variant_launch.cpp
        MVEE_LD_Loader/amd64/MVEE_LD_Loader.h
        MVEE_LD_Loader/MVEE_LD_Loader.c)
