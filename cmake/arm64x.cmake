set(CMD_LIB_NAME "canokey-minidriver")
set(CMD_DRIVERDATE "03/09/2025")
set(CMD_DRIVERVER "1.0.0.0")
set(CMD_NAME_SUFFIX " Arm64X Forwarder")

set(CMD_ARM64X_X64_DLL_NAME "canokey-minidriver-x64.dll" CACHE STRING
    "Deployment name for the x64 implementation used by the Arm64X forwarder")
set(CMD_ARM64X_ARM64_DLL_NAME "canokey-minidriver-arm64.dll" CACHE STRING
    "Deployment name for the Arm64 implementation used by the Arm64X forwarder")
set(CMD_ARM64X_FORWARDER_DLL_NAME "canokey-minidriver-arm64x.dll" CACHE STRING
    "Deployment name for the Arm64X forwarder")

foreach(required_var IN ITEMS
        CMD_ARM64X_X64_DLL
        CMD_ARM64X_ARM64_DLL
        CMD_ARM64X_LINKER
        CMD_ARM64X_ARM64RT_LIB)
  if(NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
    message(FATAL_ERROR "${required_var} is required for the Arm64X forwarder")
  endif()
  if(NOT EXISTS "${${required_var}}")
    message(FATAL_ERROR "Arm64X input does not exist: ${${required_var}}")
  endif()
endforeach()

if(NOT DEFINED CMD_ARM64X_LIB_TOOL OR "${CMD_ARM64X_LIB_TOOL}" STREQUAL "")
  get_filename_component(CMD_ARM64X_LINKER_DIR "${CMD_ARM64X_LINKER}" DIRECTORY)
  set(CMD_ARM64X_LIB_TOOL "${CMD_ARM64X_LINKER_DIR}/lib.exe")
endif()
if(NOT EXISTS "${CMD_ARM64X_LIB_TOOL}")
  message(FATAL_ERROR "Arm64X import-library tool does not exist: ${CMD_ARM64X_LIB_TOOL}")
endif()

get_filename_component(CMD_ARM64X_X64_FORWARD_MODULE "${CMD_ARM64X_X64_DLL_NAME}" NAME_WE)
get_filename_component(CMD_ARM64X_ARM64_FORWARD_MODULE "${CMD_ARM64X_ARM64_DLL_NAME}" NAME_WE)

set(CMD_ARM64X_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/arm64x")
file(MAKE_DIRECTORY "${CMD_ARM64X_BINARY_DIR}")
set(CMD_ARM64X_EMPTY_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/arm64x-empty.c")
set(CMD_ARM64X_EMPTY_ARM64 "${CMD_ARM64X_BINARY_DIR}/arm64x-empty-arm64.obj")
set(CMD_ARM64X_EMPTY_X64 "${CMD_ARM64X_BINARY_DIR}/arm64x-empty-arm64ec.obj")
set(CMD_ARM64X_ARM64_DEF "${CMD_ARM64X_BINARY_DIR}/arm64x-arm64.def")
set(CMD_ARM64X_X64_DEF "${CMD_ARM64X_BINARY_DIR}/arm64x-x64.def")
set(CMD_ARM64X_IMPLEMENTATION_DEF "${CMAKE_CURRENT_SOURCE_DIR}/canokey-minidriver.def")
set(CMD_ARM64X_IMPLEMENTATION_ARM64_LIB "${CMD_ARM64X_BINARY_DIR}/implementation-arm64.lib")
# The x64 implementation is described in the Arm64EC namespace used by the
# Arm64X linker, even though the forwarded implementation DLL is ordinary x64.
set(CMD_ARM64X_IMPLEMENTATION_X64_LIB "${CMD_ARM64X_BINARY_DIR}/implementation-arm64ec.lib")
set(CMD_ARM64X_OUTPUT_DLL "${CMAKE_CURRENT_BINARY_DIR}/${CMD_LIB_NAME}.dll")
set(CMD_ARM64X_OUTPUT_LIB "${CMAKE_CURRENT_BINARY_DIR}/${CMD_LIB_NAME}.lib")
set(CMD_ARM64X_DEPLOY_X64 "${CMAKE_CURRENT_BINARY_DIR}/${CMD_ARM64X_X64_DLL_NAME}")
set(CMD_ARM64X_DEPLOY_ARM64 "${CMAKE_CURRENT_BINARY_DIR}/${CMD_ARM64X_ARM64_DLL_NAME}")

file(GENERATE OUTPUT "${CMD_ARM64X_X64_DEF}" CONTENT
"LIBRARY ${CMD_LIB_NAME}\nEXPORTS\n  DllMain = ${CMD_ARM64X_X64_FORWARD_MODULE}.DllMain\n  CardAcquireContext = ${CMD_ARM64X_X64_FORWARD_MODULE}.CardAcquireContext\n")
file(GENERATE OUTPUT "${CMD_ARM64X_ARM64_DEF}" CONTENT
"LIBRARY ${CMD_LIB_NAME}\nEXPORTS\n  DllMain = ${CMD_ARM64X_ARM64_FORWARD_MODULE}.DllMain\n  CardAcquireContext = ${CMD_ARM64X_ARM64_FORWARD_MODULE}.CardAcquireContext\n")

add_custom_command(
  OUTPUT "${CMD_ARM64X_EMPTY_ARM64}"
  COMMAND "${CMAKE_C_COMPILER}" /nologo /c "/Fo${CMD_ARM64X_EMPTY_ARM64}"
          --target=arm64-pc-windows-msvc "${CMD_ARM64X_EMPTY_SOURCE}"
  DEPENDS "${CMD_ARM64X_EMPTY_SOURCE}"
  VERBATIM)

add_custom_command(
  OUTPUT "${CMD_ARM64X_EMPTY_X64}"
  COMMAND "${CMAKE_C_COMPILER}" /nologo /c "/Fo${CMD_ARM64X_EMPTY_X64}"
          --target=arm64ec-pc-windows-msvc "${CMD_ARM64X_EMPTY_SOURCE}"
  DEPENDS "${CMD_ARM64X_EMPTY_SOURCE}"
  VERBATIM)

add_custom_command(
  OUTPUT "${CMD_ARM64X_DEPLOY_X64}" "${CMD_ARM64X_DEPLOY_ARM64}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMD_ARM64X_X64_DLL}"
          "${CMD_ARM64X_DEPLOY_X64}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMD_ARM64X_ARM64_DLL}"
          "${CMD_ARM64X_DEPLOY_ARM64}"
  DEPENDS "${CMD_ARM64X_X64_DLL}" "${CMD_ARM64X_ARM64_DLL}"
  VERBATIM)

add_custom_command(
  OUTPUT "${CMD_ARM64X_IMPLEMENTATION_ARM64_LIB}"
  COMMAND "${CMD_ARM64X_LIB_TOOL}" /nologo /machine:arm64
          "/def:${CMD_ARM64X_IMPLEMENTATION_DEF}"
          "/out:${CMD_ARM64X_IMPLEMENTATION_ARM64_LIB}"
  DEPENDS "${CMD_ARM64X_IMPLEMENTATION_DEF}"
  VERBATIM)

add_custom_command(
  OUTPUT "${CMD_ARM64X_IMPLEMENTATION_X64_LIB}"
  COMMAND "${CMD_ARM64X_LIB_TOOL}" /nologo /machine:arm64ec
          "/def:${CMD_ARM64X_IMPLEMENTATION_DEF}"
          "/out:${CMD_ARM64X_IMPLEMENTATION_X64_LIB}"
  DEPENDS "${CMD_ARM64X_IMPLEMENTATION_DEF}"
  VERBATIM)

add_custom_command(
  OUTPUT "${CMD_ARM64X_OUTPUT_DLL}" "${CMD_ARM64X_OUTPUT_LIB}"
  COMMAND "${CMD_ARM64X_LINKER}" /nologo /dll /noentry /nodefaultlib /machine:arm64x
          "/defArm64Native:${CMD_ARM64X_ARM64_DEF}"
          "/def:${CMD_ARM64X_X64_DEF}"
          "/out:${CMD_ARM64X_OUTPUT_DLL}"
          "/implib:${CMD_ARM64X_OUTPUT_LIB}"
          "${CMD_ARM64X_EMPTY_ARM64}" "${CMD_ARM64X_EMPTY_X64}"
          "${CMD_ARM64X_IMPLEMENTATION_ARM64_LIB}" "${CMD_ARM64X_IMPLEMENTATION_X64_LIB}"
          "${CMD_ARM64X_ARM64RT_LIB}"
  DEPENDS "${CMD_ARM64X_EMPTY_ARM64}" "${CMD_ARM64X_EMPTY_X64}"
          "${CMD_ARM64X_ARM64_DEF}" "${CMD_ARM64X_X64_DEF}"
          "${CMD_ARM64X_IMPLEMENTATION_ARM64_LIB}" "${CMD_ARM64X_IMPLEMENTATION_X64_LIB}"
          "${CMD_ARM64X_ARM64RT_LIB}"
  VERBATIM)

add_custom_target(${CMD_LIB_NAME}-arm64x ALL
  DEPENDS "${CMD_ARM64X_OUTPUT_DLL}" "${CMD_ARM64X_OUTPUT_LIB}"
          "${CMD_ARM64X_DEPLOY_X64}" "${CMD_ARM64X_DEPLOY_ARM64}")

set(CMD_DEBUG_INSTALL_DIR "C:/canokey-minidriver" CACHE PATH
    "Directory used for registry-only debug deployment")
set(CMD_DEBUG_LOG_DIR "${CMD_DEBUG_INSTALL_DIR}/logs" CACHE PATH
    "Directory created for registry-configured debug logs")
configure_file("${CMAKE_CURRENT_LIST_DIR}/../canokey-minidriver.inf.in"
               "${CMAKE_CURRENT_BINARY_DIR}/${CMD_LIB_NAME}.inf" @ONLY)

add_custom_target(${CMD_LIB_NAME}-debug-install
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMD_DEBUG_INSTALL_DIR}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMD_DEBUG_LOG_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMD_ARM64X_OUTPUT_DLL}"
          "${CMD_DEBUG_INSTALL_DIR}/${CMD_ARM64X_FORWARDER_DLL_NAME}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMD_ARM64X_DEPLOY_X64}"
          "${CMD_DEBUG_INSTALL_DIR}/${CMD_ARM64X_X64_DLL_NAME}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMD_ARM64X_DEPLOY_ARM64}"
          "${CMD_DEBUG_INSTALL_DIR}/${CMD_ARM64X_ARM64_DLL_NAME}"
  DEPENDS ${CMD_LIB_NAME}-arm64x
  COMMENT "Copying Arm64X forwarder and implementation DLLs for registry-only debugging")
