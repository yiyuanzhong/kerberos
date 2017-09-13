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

#include "configure.h"

#include <json-c/json_object.h>
#include <json-c/json_util.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void configure_free(struct configure *c)
{
    struct json_object *o;
    if (!c) {
        return;
    }

    o = (struct json_object *)c->buffer;
    if (o) {
        json_object_put(o);
    }

    free(c);
}

#define Ts(x) if (!json_object_object_get_ex(o, #x, &p) || !json_object_is_type(p, json_type_string)) return -1; c->x = json_object_get_string(p)
#define Td(x) if (!json_object_object_get_ex(o, #x, &p) || !json_object_is_type(p, json_type_int)) return -1; c->x = json_object_get_int(p)
static int configure_parse(
        struct configure *c,
        struct json_object *o)
{
    struct json_object *p;

    Ts(key);
    Td(port);
    Td(milliseconds);
    Ts(admin_email);
    Ts(iptables_path);
    Ts(device);
    Ts(chain_name);
    Ts(hostname);
    Ts(denied_template_filename);
    Ts(splash_template_filename);
    Ts(welcome_template_filename);
    return 0;
}

struct configure *configure_load(const char *filename)
{
    struct json_object *o;
    struct configure *c;

    o = json_object_from_file(filename);
    if (!o) {
        return NULL;
    }

    if (!json_object_is_type(o, json_type_object)) {
        json_object_put(o);
        return NULL;
    }

    c = (struct configure *)malloc(sizeof(struct configure));
    if (!c) {
        json_object_put(o);
        return NULL;
    }

    memset(c, 0, sizeof(*c));
    c->buffer = o;

    if (configure_parse(c, o)) {
        configure_free(c);
        return NULL;
    }

    return c;
}
