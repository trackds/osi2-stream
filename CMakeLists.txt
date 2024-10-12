cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)
cmake_policy(SET CMP0042 NEW)

project (pcap_addon)
include(ExternalProject)

add_definitions(-DNAPI_VERSION=7)
add_definitions(-DHAVE_REMOTE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB SOURCE_FILES "src/*.c")
message("files: " ${SOURCE_FILES})
message("target_arch:" ${CMAKE_SYSTEM_PROCESSOR})


if(WIN32)
  ExternalProject_Add(npcap_sdk
    URL https://npcap.com/dist/npcap-sdk-1.13.zip
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
  )
  ExternalProject_Get_Property(npcap_sdk BINARY_DIR)
  
  message("BINARY_DIR: " ${BINARY_DIR})
  set(NPCAP_INCLUDE_DIR ${BINARY_DIR}/Include)
  set(NPCAP_LIB_DIR ${BINARY_DIR}/Lib)
  
  include_directories(${CMAKE_JS_INC} ${NPCAP_INCLUDE_DIR})
  
  if (CMAKE_CL_64)
    set(LIBPCAP ${NPCAP_LIB_DIR}/x64/wpcap.lib ${NPCAP_LIB_DIR}/x64/Packet.lib)
  else()
    set(LIBPCAP ${NPCAP_LIB_DIR}/wpcap.lib ${NPCAP_LIB_DIR}/Packet.lib)
  endif()
  
  message("LIBPCAP: " ${LIBPCAP})
  
elseif(UNIX)
  ExternalProject_Add(libpcap_sdk
    GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap.git
    GIT_TAG libpcap-1.10.5
    CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}" "-DCMAKE_C_FLAGS='-fPIC'"
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}
  )
  ExternalProject_Get_Property(libpcap_sdk BINARY_DIR INSTALL_DIR)
  set(LIBPCAP ${INSTALL_DIR}/lib/libpcap.a)
  include_directories(${CMAKE_JS_INC} ${INSTALL_DIR}/include)
  message("INSTALL_DIR: " ${INSTALL_DIR})
  message("LIBPCAP: " ${LIBPCAP})
endif()
  
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} ${LIBPCAP})
  

if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
  # Generate node.lib
  execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()