# CMakeLists file for Sasl module
#
# copyright © 2026 by Hatem Nabli

cmake_minimum_required(VERSION 3.20)
set(This Sasl)


set(Headers
    include/Sasl/Login.hpp
    include/Sasl/Plain.hpp
    include/Sasl/Scram.hpp
)

set(Sources
    src/Login.cpp
    src/Plain.cpp
    src/Scram.cpp
)

add_library(${This} STATIC ${Sources} ${Headers})
set_target_properties(${This} PROPERTIES
    FOLDER Libraries
)
target_include_directories(${This} PUBLIC include)
target_link_libraries(
    SystemUtils
)

add_subdirectory(test)