/* Copyright 2017 yiyuanzhong@gmail.com (Yiyuan Zhong)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KERBEROS_HTTPD_H
#define KERBEROS_HTTPD_H

#include <stdint.h>

struct configure;
struct httpd;
struct iptables;

extern void httpd_stop(struct httpd *h);
extern struct httpd *httpd_start(
        const struct configure *c,
        struct iptables *i);

#endif /* KERBEROS_HTTPD_H */
