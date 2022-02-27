cmake_minimum_required(VERSION 3.10)
project(SEALDemo VERSION 1.0)
add_executable(simplecalc simplecalc.cpp)

find_package(SEAL)
target_link_libraries(simplecalc SEAL::seal)
