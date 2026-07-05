# CMakeLists.txt for Sasl tests module.
#
# copyright © 2026 by Hatem Nabli.

cmake_minimum_required(VERSION 3.20)
set(This SaslTests)

set(Sources
    src/LoginTests.cpp
    src/PlainTests.cpp
    src/ScramTests.cpp
)

add_executable(${This} ${Sources})
set_target_properties(${This} PROPERTIES FOLDER Tests)

target_include_directories(${This} PRIVATE ..)

target_link_libraries(${This} PUBLIC
    gtest_main
    Sasl
    SystemUtils
)

add_test(
    NAME ${This}
    COMMAND ${This}
)