cmake_minimum_required (VERSION 3.8)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("canokey-mini-driver")

file (GLOB SOURCES *.c *.cpp)
file (GLOB HEADERS *.h)

add_library (canokey-minidriver SHARED ${SOURCES} ${HEADERS})
target_link_libraries (canokey-minidriver PRIVATE "winscard.dll")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET canokey-minidriver PROPERTY CXX_STANDARD 20)
endif()
