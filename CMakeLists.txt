cmake_minimum_required (VERSION 3.12)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

macro(add_cxx_flag flag)
  message(STATUS "Configure with flag '${flag}'")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}")
endmacro()

project (ethos_checker)

# >> 2-valued: ON OFF
#    > for options where we don't need to detect if set by user (default: OFF)
option(BUILD_STATIC          "Build static binary" OFF)

if(BUILD_STATIC)
  set(BUILD_SHARED_LIBS OFF)
  set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  # Linking system libraries statically is strongly discouraged on macOS.
  # See https://developer.apple.com/library/archive/qa/qa1118/_index.html
  if(NOT APPLE)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
  endif()
endif()

set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package(GMP REQUIRED)
set(LIBRARIES ${LIBRARIES} ${GMP_LIBRARIES})
include_directories(${GMP_INCLUDE_DIR})

if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Defaulting to release build.")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_cxx_flag("-Wall")
add_cxx_flag("-Wno-deprecated")
add_cxx_flag("-std=gnu++17")

if(WIN32)
  add_definitions(-DUSE_CPP_FILESYSTEM)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_cxx_flag("-g")
  add_definitions(-DEO_ASSERTIONS)
  add_definitions(-DEO_TRACING)
  message(STATUS "Configured debug build.")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
  message(STATUS "Configured release build.")
else()
  message(FATAL_ERROR "Invalid build type '${CMAKE_BUILD_TYPE}'")
endif()

enable_testing()

include_directories(src)
add_subdirectory(src)
add_subdirectory(tests)

