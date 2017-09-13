# Copyright 2017 yiyuanzhong@gmail.com (Yiyuan Zhong)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


AUTOMAKE_OPTIONS = foreign nostdinc
sbin_PROGRAMS = kerberos
SUBDIRS = .

kerberos_CPPFLAGS = \
        @libjson_c_CFLAGS@ \
        @libcrypto_CFLAGS@ \
        @libmicrohttpd_CFLAGS@

kerberos_LDADD = \
        @libjson_c_LIBS@ \
        @libcrypto_LIBS@ \
        @libmicrohttpd_LIBS@

kerberos_SOURCES = \
        configure.c \
        configure.h \
        httpd.h \
        httpd.c \
        iptables.c \
        iptables.h \
        main.c
