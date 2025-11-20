set(CAPTURER_TARGET_NAME Capturer)

set(CAPTURER_SOURCES
    XdpCapturer.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/src/)
include_directories(${CMAKE_SOURCE_DIR}/src/Utilities)

# make DPDK system headers visible to all directories
include_directories(/usr/include/x86_64-linux-gnu/dpdk /usr/include/dpdk)

add_library(${CAPTURER_TARGET_NAME} STATIC ${CAPTURER_SOURCES})

# ensure DPDK headers that use SSSE3 intrinsics compile correctly
target_compile_options(${CAPTURER_TARGET_NAME} PUBLIC
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-mssse3>
)