cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)
cmake_policy(SET CMP0042 NEW)

project (pcap_addon)

add_definitions(-DNAPI_VERSION=7)
add_definitions(-DHAVE_REMOTE)

include_directories(${CMAKE_JS_INC} ./lib/winpcap/Include)

file(GLOB SOURCE_FILES "src/*.c")
message("files: " ${SOURCE_FILES})
message("target_arch:" ${CMAKE_SYSTEM_PROCESSOR})

if (CMAKE_CL_64)
  find_library(LIBWPCAP NAMES wpcap PATHS ./lib/winpcap/lib/x64)
  find_library(LIBPACKET NAMES Packet packet PATHS ./lib/winpcap/lib/x64)
else()
  find_library(LIBWPCAP NAMES wpcap PATHS ./lib/winpcap/lib/)
  find_library(LIBPACKET NAMES Packet packet PATHS ./lib/winpcap/lib/)
endif()

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} ${LIBWPCAP} ${LIBPACKET})

if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
  # Generate node.lib
  execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()