cmake_minimum_required(VERSION 3.22)
project(packet_inspector CXX)

set(PROJECT_NAME packet_inspector)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(MAIN_SOURCES
    src/PacketInspector.cpp
)

# Ignore "deprecated-declarations" warnings
add_compile_options(-Wno-deprecated-declarations)

add_subdirectory(src)

add_executable(${PROJECT_NAME} ${MAIN_SOURCES})

# target_link_libraries(${PROJECT_NAME}
#     PUBLIC
#         -lpcap
# )