cmake_minimum_required(VERSION 2.8)

project (syslog-ng-serviced)
set(CMAKE_BUILD_TYPE Debug)

find_package (Threads)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)
include_directories(${GLIB_PKG_INCLUDE_DIRS})

add_library(syslog-ng-serviced SHARED serviced.c)
include_directories(/usr/local/include)
include_directories(/usr/local/include/eventlog)
include_directories(/usr/local/include/syslog-ng)
set_target_properties(syslog-ng-serviced PROPERTIES PREFIX "")
set_target_properties(syslog-ng-serviced PROPERTIES SOVERSION 1)
target_link_libraries(syslog-ng-serviced /usr/local/lib/libserviced.so)
target_link_libraries(syslog-ng-serviced /usr/local/lib/libsyslog-ng.so)
target_link_libraries(syslog-ng-serviced ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS syslog-ng-serviced LIBRARY DESTINATION lib)
