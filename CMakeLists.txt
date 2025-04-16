cmake_minimum_required (VERSION 3.15)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("canokey-mini-driver" VERSION 1.0.0.0 LANGUAGES C)

option (BUILD_SHARED_LIBS "Build using shared libraries" OFF)
if (BUILD_SHARED_LIBS)
  message (FATAL_ERROR "all dependencies must be built statically")
endif ()
add_subdirectory (external/canokey-pkcs11)
include_directories (external/canokey-pkcs11/include)

set (CMAKE_VERBOSE_MAKEFILE OFF)
set (CMAKE_C_STANDARD 17)

file (GLOB SOURCES *.c *.cpp rsa/*.c)
file (GLOB HEADERS *.h rsa/*.h)

set (CMD_DRIVERDATE "03/09/2025")
set (CMD_DRIVERVER ${CMAKE_PROJECT_VERSION})
set (CMD_LIB_NAME "canokey-minidriver")

add_library (${CMD_LIB_NAME} SHARED ${SOURCES} ${HEADERS})
target_link_libraries (${CMD_LIB_NAME} PRIVATE "winscard.lib" canokey_pkcs11)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions (CMD_VERBOSE DBG_NCOLOR)
  set (CMD_NAME_SUFFIX " Debug (${CMAKE_HOST_SYSTEM_PROCESSOR} ${CMD_DRIVERVER} ${CMD_DRIVERDATE})")
  target_link_libraries (${CMD_LIB_NAME} PRIVATE "dbghelp.lib")
else ()
  add_compile_definitions (NDBG)
endif ()

configure_file ("${CMD_LIB_NAME}.inf.in" "${CMD_LIB_NAME}.inf" @ONLY)

if (MSVC)
  target_compile_options(${CMD_LIB_NAME} PRIVATE /W4)
else ()
  target_compile_options(${CMD_LIB_NAME} PRIVATE -Wall -Wextra)
endif ()

# export necessary symbols for BaseCSP to use
target_link_options(${CMD_LIB_NAME} PRIVATE /DEF:${CMAKE_CURRENT_SOURCE_DIR}/${CMD_LIB_NAME}.def)
