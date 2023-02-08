cmake_minimum_required (VERSION 3.1.0 FATAL_ERROR)
project (TinyGarble
  VERSION 3.0.0
  LANGUAGES CXX)

##############
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.6.3")
    message(FATAL_ERROR "Insufficient gcc version, should be at least 4.6.3")
  endif()
endif()

#############
enable_testing()
include_directories (${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR})

##############
# build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

if (CMAKE_BUILD_TYPE MATCHES Debug)
  message("Debug build.")
elseif (CMAKE_BUILD_TYPE MATCHES Release)
  message("Release build.")
else()
  message("Some other build type.")
endif ()

###############
# Compiler flags
set(CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} -Wall -Wno-strict-aliasing -march=native")

# set -lrt for minunit testing lib.
if (UNIX)
  set(CMAKE_CXX_STANDARD_LIBRARIES "-lrt -lpthread -ldl")
endif (UNIX)

set (CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

###############
# Library

## Boost
set (Boost_USE_STATIC_LIBS OFF)
set (Boost_USE_MULTITHREADED ON)
set (Boost_USE_STATIC_RUNTIME OFF)
find_package (Boost 1.45.0
  REQUIRED
  COMPONENTS program_options)

if (Boost_FOUND)
  include_directories (${Boost_INCLUDE_DIRS})
endif (Boost_FOUND)

## OpenSSL
find_package (OpenSSL)

if (OPENSSL_FOUND)
	include_directories (${OPENSSL_INCLUDE_DIR})
endif (OPENSSL_FOUND)

###############
# Options
option (ENABLE_DUMP "Enable dump hex feature" OFF)
option (ENABLE_LOG "Enable log feature" OFF)
if (CMAKE_BUILD_TYPE MATCHES Debug)
	message("Turn Log on.")
	SET(ENABLE_LOG ON BOOL "Turn on logs in debug mode.")
endif (CMAKE_BUILD_TYPE MATCHES Debug)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "tinygarble_config.h.in"
  "tinygarble_config.h")
###############
# Subdirectory
add_library (Util_Log OBJECT
  "log.cpp")

add_library (Util_Util OBJECT
  "util.cpp")


add_library (Garbled_Circuit_Garbled_Circuit_Util OBJECT
  "garbled_circuit_util.cpp")
add_library (Garbled_Circuit_Garbled_Circuit_High_Mem OBJECT
  "garbled_circuit_high_mem.cpp")  
add_library (Garbled_Circuit_Garbled_Circuit OBJECT
  "garbled_circuit.cpp")
  add_library (BN_lib OBJECT
  "BN.cpp")

add_executable(TinyGarble
  "garbled_circuit_main.cpp"
  "$<TARGET_OBJECTS:Util_Util>"
  "$<TARGET_OBJECTS:BN_lib>"
  "$<TARGET_OBJECTS:Garbled_Circuit_Garbled_Circuit>"
  "$<TARGET_OBJECTS:Garbled_Circuit_Garbled_Circuit_Util>"
  "$<TARGET_OBJECTS:Garbled_Circuit_Garbled_Circuit_High_Mem>"
  "$<TARGET_OBJECTS:SCD_SCD>"
  "$<TARGET_OBJECTS:Util_Log>")

  if (OPENSSL_FOUND)
	target_link_libraries(TinyGarble ${OPENSSL_LIBRARIES})
endif (OPENSSL_FOUND)
if (Boost_FOUND)
  target_link_libraries(TinyGarble ${Boost_LIBRARIES})
endif (Boost_FOUND)

  add_subdirectory ("scd")
