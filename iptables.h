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

#ifndef KERBEROS_IPTABLES_H
#define KERBEROS_IPTABLES_H

struct configure;
struct iptables;
struct sockaddr;
struct sockaddr_in;

extern struct iptables *iptables_start(const struct configure *c);
extern void iptables_cleanup(struct iptables *i);
extern void iptables_stop(struct iptables *i);

extern int iptables_verify(
        struct iptables *i,
        const struct sockaddr *eth,
        const struct sockaddr_in *in);

extern int iptables_allow(
        struct iptables *i,
        const struct sockaddr *eth,
        const struct sockaddr_in *in,
        int milliseconds);

extern int iptables_deny(
        struct iptables *i,
        const struct sockaddr *eth,
        const struct sockaddr_in *in);

#endif /* KERBEROS_IPTABLES_H */
