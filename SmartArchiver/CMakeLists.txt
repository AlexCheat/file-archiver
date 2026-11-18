cmake_minimum_required(VERSION 3.16)

project(SmartArchiver CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_library(sarc_core STATIC
    sarc_codec.cpp
    crc32.cpp
    sha256.cpp
    aes256.cpp
    random.cpp
    classifier.cpp
    knapsack.cpp
    archive_writer.cpp
    archive_reader.cpp
)
target_include_directories(sarc_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(sarc main.cpp)
target_link_libraries(sarc PRIVATE sarc_core)

enable_testing()
add_executable(sarc_tests tests/test_main.cpp)
target_link_libraries(sarc_tests PRIVATE sarc_core)
add_test(NAME sarc_tests COMMAND sarc_tests)

if(MSVC)
    target_compile_options(sarc_core PRIVATE /W4)
else()
    target_compile_options(sarc_core PRIVATE -Wall -Wextra)
endif()
