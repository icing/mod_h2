# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Read README.cmake before using this.

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(MOD_HTTP2 C)

INCLUDE(CheckCSourceCompiles)

IF(EXISTS "${NGHTTP2_LIBRARIES}")
  MESSAGE(STATUS "have NGHTTP2_LIBRARIES")
  MESSAGE(STATUS "NGHTTP2_LIBRARIES >${NGHTTP2_LIBRARIES}<")
  SET(default_nghttp2_libraries "${NGHTTP2_LIBRARIES}")
ELSE()
  SET(default_nghttp2_libraries "-lnghttp2")
ENDIF()

IF(EXISTS "${PROXY_LIBRARY}")
  MESSAGE(STATUS "have PROXY_LIBRARY")
  MESSAGE(STATUS "PROXY_LIBRARY >${PROXY_LIBRARY}<")
  SET(default_proxy_libraries "${PROXY_LIBRARY}")
ENDIF()

CHECK_C_SOURCE_COMPILES("#include <sys/types.h>
int main() {
  ssize_t err= -1;
return 1;}" HAS_ssize_t)

INCLUDE_DIRECTORIES(${APR_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${APRUTIL_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${APACHE_INCLUDE_DIR})

SET(mod_http2_extra_includes         ${NGHTTP2_INCLUDE_DIR})
SET(mod_http2_extra_libs             ${default_nghttp2_libraries})

SET(mod_http2_sources
  mod_http2/h2_bucket_beam.c     mod_http2/h2_bucket_eos.c
  mod_http2/h2_c1.c              mod_http2/h2_c1_io.c
  mod_http2/h2_c2.c              mod_http2/h2_c2_filter.c
  mod_http2/h2_config.c          mod_http2/h2_conn_ctx.c
  mod_http2/h2_mplx.c            mod_http2/h2_headers.c
  mod_http2/h2_protocol.c        mod_http2/h2_push.c
  mod_http2/h2_request.c         mod_http2/h2_session.c
  mod_http2/h2_stream.c          mod_http2/h2_switch.c
  mod_http2/h2_util.c            mod_http2/h2_workers.c
  mod_http2/h2_ws.c
)


SET(mod_proxy_http2_extra_includes         ${NGHTTP2_INCLUDE_DIR})
SET(mod_proxy_http2_extra_libs             ${default_nghttp2_libraries} ${default_proxy_libraries})
SET(mod_proxy_http2_extra_sources
  mod_http2/h2_proxy_session.c   mod_http2/h2_proxy_util.c
)

ADD_LIBRARY(mod_http2 MODULE ${mod_http2_sources} mod_http2/mod_http2.c)
SET_TARGET_PROPERTIES(mod_http2 PROPERTIES PREFIX "")
SET_TARGET_PROPERTIES(mod_http2 PROPERTIES SUFFIX ".so")
IF(${HAS_ssize_t})
  MESSAGE(STATUS "have ssize_t")
ELSE()
  SET(mod_http2_extra_defines          ssize_t=long)
  SET_TARGET_PROPERTIES(mod_http2 PROPERTIES COMPILE_DEFINITIONS ${mod_http2_extra_defines})
ENDIF()
target_link_libraries(mod_http2 ${default_nghttp2_libraries} ${APACHE_LIBRARY} ${APRUTIL_LIBRARY} ${APR_LIBRARY})

ADD_LIBRARY(mod_proxy_http2 MODULE ${mod_proxy_http2_extra_sources} mod_http2/mod_proxy_http2.c)
SET_TARGET_PROPERTIES(mod_proxy_http2 PROPERTIES PREFIX "")
SET_TARGET_PROPERTIES(mod_proxy_http2 PROPERTIES SUFFIX ".so")
IF(${HAS_ssize_t})
  MESSAGE(STATUS "have ssize_t")
ELSE()
  SET(mod_proxy_http2_extra_defines    ssize_t=long)
  SET_TARGET_PROPERTIES(mod_proxy_http2 PROPERTIES COMPILE_DEFINITIONS ${mod_proxy_http2_extra_defines})
ENDIF()
target_link_libraries(mod_proxy_http2 ${mod_proxy_http2_extra_libs} ${APACHE_LIBRARY} ${APRUTIL_LIBRARY} ${APR_LIBRARY})
