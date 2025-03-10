cmake_minimum_required (VERSION 3.8)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("canokey-mini-driver" VERSION 1.0.0.0)

file (GLOB SOURCES *.c *.cpp)
file (GLOB HEADERS *.h)

set (CMD_DRIVERDATE "03/09/2025")
set (CMD_DRIVERVER ${CMAKE_PROJECT_VERSION})
set (CMD_LIB_NAME "canokey-minidriver")
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  set (CMD_NAME_SUFFIX " Debug (${CMAKE_HOST_SYSTEM_PROCESSOR} ${CMD_DRIVERVER} ${CMD_DRIVERDATE})")
endif ()
configure_file ("canokey_minidriver.inf.in" "canokey_minidriver.inf" @ONLY)

add_library (canokey-minidriver SHARED ${SOURCES} ${HEADERS})
target_link_libraries (canokey-minidriver PRIVATE "winscard.dll")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET canokey-minidriver PROPERTY CXX_STANDARD 20)
endif()
