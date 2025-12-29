cmake_minimum_required(VERSION 3.22)
project(packet_inspector CXX)

set(PROJECT_NAME packet_inspector)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
    src/main.cpp
    src/OptionHandler.cpp
    src/Session.cpp
    src/SessionCollection.cpp
)

# Add compiler definition for debug targets
if (CMAKE_BUILD_TYPE STREQUAL "DEBUG")
    message(STATUS "Debug and verbose mode enabled")

    add_compile_definitions(BE_VERBOSE=1)
    add_compile_definitions(DO_DEBUGGING=1)
endif()

# Ignore "deprecated-declarations" warnings
add_compile_options(-Wno-deprecated-declarations)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME}
    PUBLIC
        -lpcap
)