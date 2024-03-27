Experimental cmake-based build support for mod_h2 on Microsoft Windows

Prerequisites
-------------

The following tools must be in PATH:

* cmake, version 2.8 or later
* compiler and linker and related tools

The following support libraries are mandatory:
* APR and APR_UTIL built using cmake
* nghttp2 built using cmake
* httpd built using cmake (Read the README.cmake there).

How to build
------------

1. cd to a clean directory for building (i.e., don't build in your
   source tree)

2. Make sure cmake and build environment are in PATH and set the platform (call vcvars64 for example).

3. cmake -G "some backend, like "'Visual Studio 17 2022'"
   -DAPR_INCLUDE_DIR=/path/to/aprinst/include/
   -DAPRUTIL_INCLUDE_DIR=/path/to/aprutilinst/include/
   -DAPACHE_INCLUDE_DIR=/path/to/httpdinst/include/
   -DAPR_LIBRARY=/path/to/aprinst/lib/libapr-1.lib
   -DAPRUTIL_LIBRARY=/path/to/aprutilinst/lib/libaprutil-1.lib
   -DAPACHE_LIBRARY=/path/to/httpdinst/lib/libhttpd.lib
   -DPROXY_LIBRARY=/path/to/httpdinst/lib/mod_proxy.lib 
   -DNGHTTP2_LIBRARIES=/path/to/nghttp2inst/lib/nghttp2.lib
   -DNGHTTP2_INCLUDE_DIR=/path/to/nghttp2inst/include/
   path/to/mod_h2sources

4. Build using the chosen generator (e.g., "MSBuild ALL_BUILD.vcxproj -t:build -p:Configuration=Release"
   for cmake's "Visual Studio 17 2022" generator).

5. copy the *.so files from Release to /path/to/httpdinst/modules

Note: The apachelounge distribution doesn't contain nghttp2.h.
      Use cmake from nghttp2 to build the library and copy the include file.
