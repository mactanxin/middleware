cmake_minimum_required(VERSION 2.8)

project (libesrviced)
set(CMAKE_BUILD_TYPE Debug)

find_package (Threads)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(libserviced SHARED serviced.c)
include_directories(/usr/local/include)
set_target_properties(libserviced PROPERTIES PREFIX "")
set_target_properties(libserviced PROPERTIES SOVERSION 1)
target_link_libraries(libserviced /usr/local/lib/libdispatcherclient.so)
target_link_libraries(libserviced ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS libserviced LIBRARY DESTINATION lib)
install(FILES serviced.h DESTINATION include)
