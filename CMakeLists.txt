## ****************************************************************************
## DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
##
## Copyright 2022 Tino Jungebloud <tino@jungebloud.de>
## 
##
## This confidential and proprietary software may be disclosed,
## used, or copied only as authorized by a license agreement from
## the copyright owner
## ****************************************************************************

# Build:
#
#   mkdir io.mbse.mora.score.cvss3.build
#   cd io.mbse.mora.score.cvss3.build
#   cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release ..\io.mbse.mora.score.cvss3
#
#   cmake --build .
#   bin\test__io.mbse.mora.score.cvss.exe -l all

cmake_minimum_required(VERSION 3.20)
project(mora.score LANGUAGES CXX)

set(PROJECT_DESCRIPTION "Methods and Application for Information Risk Assessment")
set(MORA_SOURCE_ROOTDIR "${PROJECT_SOURCE_DIR}/..")
set(MORA_BINARY_ROOTDIR "${PROJECT_BINARY_DIR}/..")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Boost C++ Libraries ---------------------------------------------------------
set(Boost_USE_RELEASE_LIBS ON)
set(Boost_USE_DEBUG_LIBS OFF)
set(Boost_USE_STATIC_RUNTIME OFF)
set(Boost_USE_MULTITHREADED OFF)
find_package(Boost 1.78.0)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories(${Boost_LIBRARIES})
endif()

# -----------------------------------------------------------------------------

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
  ${PROJECT_BINARY_DIR}/bin
)

include_directories(${CMAKE_SOURCE_DIR}/src)

add_subdirectory(src)
add_subdirectory(tests)

#EOF
