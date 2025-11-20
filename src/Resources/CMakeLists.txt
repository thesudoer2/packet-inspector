set(RESOURCES_TARGET_NAME Resources)

set(RESOURCES_SOURCES
    DpdkResourceManager.cpp
)

add_library(${RESOURCES_TARGET_NAME} STATIC ${RESOURCES_SOURCES})

# # Include dpdk header pathes
# target_include_directories(${RESOURCES_TARGET_NAME} INTERFACE SYSTEM
#     /usr/include/x86_64-linux-gnu/dpdk
#     /usr/include/dpdk
# )

# make DPDK system headers visible to all directories
target_include_directories(${RESOURCES_TARGET_NAME} PRIVATE
    /usr/include/x86_64-linux-gnu/dpdk /usr/include/dpdk
)

target_include_directories(${RESOURCES_TARGET_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/src/Utilities
)

# expose includes to consumers:
target_include_directories(${RESOURCES_TARGET_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# ensure DPDK headers that use SSSE3 intrinsics compile correctly
target_compile_options(${RESOURCES_TARGET_NAME} PUBLIC
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-mssse3>
)