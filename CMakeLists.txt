cmake_minimum_required(VERSION 3.16.0)

project(SwiftMetalWin32
  LANGUAGES C CXX)
  #Swift

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/Modules)

option(WITH_SWIFT_LOG "Enable logging through swift-log" NO)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_Swift_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/swift)

if(WITH_SWIFT_LOG)
  find_package(swift-log CONFIG QUIET)
endif()

include(SwiftSupport)
#add_subdirectory(core/libobjc2)
add_subdirectory(frameworks)
add_subdirectory(usr)

#add_subdirectory(src)
#add_subdirectory(examples)

add_subdirectory(tools)

#export(TARGETS SwiftWin32
#  FILE SwiftWin32Config.cmake)