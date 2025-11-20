set(LOGGER_TARGET_NAME Logger)

set(LOGGER_SOURCES
    Logger.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/src/Utilities/)

add_library(${LOGGER_TARGET_NAME} STATIC ${LOGGER_SOURCES})