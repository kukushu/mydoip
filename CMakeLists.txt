cmake_minimum_required(VERSION 3.12)
project(doip_dcm_uds_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(dcm STATIC src/dcm/dcm_service.cpp)
target_include_directories(dcm PUBLIC src)

add_executable(doip_server src/app/server.cpp)
target_link_libraries(doip_server PRIVATE dcm)

add_executable(doip_client src/app/client.cpp)
target_link_libraries(doip_client PRIVATE dcm)
