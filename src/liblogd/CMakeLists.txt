cmake_minimum_required(VERSION 2.8)

project (libesrviced)
set(CMAKE_BUILD_TYPE Debug)

find_package (Threads)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(liblogd SHARED liblogd.c)
include_directories(/usr/local/include)
set_target_properties(liblogd PROPERTIES PREFIX "")
set_target_properties(liblogd PROPERTIES SOVERSION 1)
target_link_libraries(liblogd /usr/local/lib/libdispatcherclient.so)
target_link_libraries(liblogd ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS liblogd LIBRARY DESTINATION lib)
install(FILES liblogd.h DESTINATION include)
