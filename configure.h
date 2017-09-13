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

#include <string.h>
#ifndef KERBEROS_CONFIGURE_H
#define KERBEROS_CONFIGURE_H

#include <stdint.h>

struct configure {
    uint16_t port;
    int milliseconds;
    const char *key;
    const char *admin_email;
    const char *iptables_path;
    const char *device;
    const char *chain_name;
    const char *hostname;
    const char *favicon_filename;
    const char *denied_template_filename;
    const char *splash_template_filename;
    const char *welcome_template_filename;

    void *buffer; /* Don't refer to this one directly */
}; /* struct configure */

extern struct configure *configure_load(const char *filename);
extern void configure_free(struct configure *c);

#endif /* KERBEROS_CONFIGURE_H */
