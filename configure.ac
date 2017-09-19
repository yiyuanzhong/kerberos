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


AC_PREREQ([2.59])
AC_INIT([kerberos], [1.0], [yiyuanzhong@gmail.com])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AM_INIT_AUTOMAKE

AC_PROG_CC
AM_PROG_CC_C_O

AC_LANG([C])

PKG_CHECK_MODULES([libjson_c], [json-c])
PKG_CHECK_MODULES([libcrypto], [libcrypto])
PKG_CHECK_MODULES([libmicrohttpd], [libmicrohttpd])

AC_SEARCH_LIBS([pthread_mutex_lock], [pthread])

AC_OUTPUT
