cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find threading library
find_package(Threads REQUIRED)

# Shared source files (used by both targets)
set(SHARED_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# ============================================================
# Target 1: Simple single-threaded DPI engine (v3.0)
# ============================================================
add_executable(dpi_working
    src/main_working.cpp
    ${SHARED_SOURCES}
)
target_compile_options(dpi_working PRIVATE -Wall -O2)
target_link_libraries(dpi_working PRIVATE Threads::Threads)

# ============================================================
# Target 2: Multi-threaded DPI engine
# ============================================================
add_executable(dpi_engine
    src/dpi_mt.cpp
    ${SHARED_SOURCES}
)
target_compile_options(dpi_engine PRIVATE -Wall -O2)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# ============================================================
# Target 3: Real-time Live Capture DPI (Windows only)
# ============================================================
if(WIN32)
    add_executable(dpi_live
        src/dpi_live.cpp
    )
    target_compile_options(dpi_live PRIVATE -Wall -O2)
    target_link_libraries(dpi_live PRIVATE ws2_32 iphlpapi)
    message(STATUS "Configured dpi_live (Windows live capture)")
endif()

message(STATUS "Configured DPI Engine targets: dpi_working, dpi_engine, dpi_live(Win)")
