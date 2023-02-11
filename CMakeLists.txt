cmake_minimum_required(VERSION 3.23)
project(tiny_dns_server)

set(CMAKE_CXX_STANDARD 17)

add_executable(tiny_dns_server main.cpp xdns.cpp xdns.h)
