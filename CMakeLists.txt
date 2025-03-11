cmake_minimum_required (VERSION 3.8)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("canokey-mini-driver" VERSION 1.0.0.0)

set (CMAKE_VERBOSE_MAKEFILE OFF)
set (CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

file (GLOB SOURCES *.c *.cpp)
file (GLOB HEADERS *.h)

set (CMD_DRIVERDATE "03/09/2025")
set (CMD_DRIVERVER ${CMAKE_PROJECT_VERSION})
set (CMD_LIB_NAME "canokey-minidriver")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions (CMD_VERBOSE DBG_NCOLOR)
  set (CMD_NAME_SUFFIX " Debug (${CMAKE_HOST_SYSTEM_PROCESSOR} ${CMD_DRIVERVER} ${CMD_DRIVERDATE})")
else ()
  add_compile_definitions (NDBG)
endif ()

configure_file ("${CMD_LIB_NAME}.inf.in" "${CMD_LIB_NAME}.inf" @ONLY)
add_library (${CMD_LIB_NAME} SHARED ${SOURCES} ${HEADERS})
target_link_libraries (${CMD_LIB_NAME} PRIVATE "winscard.dll")

if (MSVC)
  target_compile_options(${CMD_LIB_NAME} PRIVATE /W4)
else ()
  target_compile_options(${CMD_LIB_NAME} PRIVATE -Wall -Wextra)
endif ()

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ${CMD_LIB_NAME} PROPERTY CXX_STANDARD 20)
endif ()
