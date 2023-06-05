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

.PHONY: h2ws

# http/2 websocket client

bin_PROGRAMS       = h2ws

h2ws_CFLAGS  = -g -I../src -std=c99 -D_GNU_SOURCE @WERROR_CFLAGS@
h2ws_LDFLAGS = @LDFLAGS@ -lnghttp2

H2WS_OBJECTS = \
    h2ws.c

H2WS_HFILES =

h2ws_SOURCES = $(H2WS_HFILES) $(H2WS_OBJECTS)
