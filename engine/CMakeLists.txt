cmake_minimum_required(VERSION 3.24)
project(KryvnixEngine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(kryvnix_engine
    src/main.cpp
)

target_include_directories(kryvnix_engine PRIVATE include)

if(WIN32)
    target_compile_definitions(kryvnix_engine PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _UNICODE UNICODE)
endif()
