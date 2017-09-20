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

#include "iptables.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "configure.h"

struct node {
    struct node *next;
    struct node *priv;
    struct sockaddr eth;
    struct sockaddr_in in;
    int64_t deadline;
}; /* struct node */

struct iptables {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    const char *device;
    const char *chain;
    const char *iptables;
    struct node *allowed;
    int mark;
}; /* struct iptables */

static void iptables_node_add(struct iptables *i, struct node *p)
{
    p->priv = NULL;
    p->next = i->allowed;
    if (i->allowed) {
        i->allowed->priv = p;
    }
    i->allowed = p;
}

static void iptables_node_remove(struct iptables *i, struct node *p)
{
    if (p->priv) {
        p->priv->next = p->next;
    } else {
        i->allowed = p->next;
    }

    if (p->next) {
        p->next->priv = p->priv;
    }
}

static int iptables_insert(
        const struct iptables *i,
        const struct sockaddr *eth,
        const struct sockaddr_in *in)
{
    char buffer[1024];
    char smac[64];
    char sip[32];

    inet_ntop(AF_INET, &in->sin_addr, sip, sizeof(sip));
    sprintf(smac, "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)eth->sa_data[0],
            (unsigned char)eth->sa_data[1],
            (unsigned char)eth->sa_data[2],
            (unsigned char)eth->sa_data[3],
            (unsigned char)eth->sa_data[4],
            (unsigned char)eth->sa_data[5]);

    snprintf(buffer, sizeof(buffer),
            "%s -t mangle -I %s -s %s -m mac --mac-source %s -j MARK --set-xmark 0x%x/0x%x",
            i->iptables, i->chain, sip, smac, i->mark, i->mark);

    return system(buffer);
}

static int iptables_delete(
        const struct iptables *i,
        const struct sockaddr *eth,
        const struct sockaddr_in *in)
{
    char buffer[1024];
    char smac[64];
    char sip[32];

    inet_ntop(AF_INET, &in->sin_addr, sip, sizeof(sip));
    snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)eth->sa_data[0],
             (unsigned char)eth->sa_data[1],
             (unsigned char)eth->sa_data[2],
             (unsigned char)eth->sa_data[3],
             (unsigned char)eth->sa_data[4],
             (unsigned char)eth->sa_data[5]);

    snprintf(buffer, sizeof(buffer),
            "%s -t mangle -D %s -s %s -m mac --mac-source %s -j MARK --set-xmark 0x%x/0x%x",
            i->iptables, i->chain, sip, smac, i->mark, i->mark);

    return system(buffer);
}

void iptables_stop(struct iptables *i)
{
    struct node *p;
    struct node *q;

    if (!i) {
        return;
    }

    for (p = i->allowed; p;) {
        q = p;
        p = p->next;
        iptables_delete(i, &q->eth, &q->in);
        free(q);
    }

    pthread_cond_destroy(&i->cond);
    pthread_mutex_destroy(&i->mutex);
    free(i);
}

struct iptables *iptables_start(const struct configure *c)
{
    struct iptables *i;

    if (!c || !c->iptables_path || !c->device) {
        return NULL;
    }

    i = (struct iptables *)malloc(sizeof(struct iptables));
    if (!i) {
        return NULL;
    }

    memset(i, 0, sizeof(*i));
    if (pthread_mutex_init(&i->mutex, NULL)) {
        free(i);
        return NULL;
    }

    if (pthread_cond_init(&i->cond, NULL)) {
        pthread_mutex_destroy(&i->mutex);
        free(i);
        return NULL;
    }

    i->iptables = c->iptables_path;
    i->mark = c->iptables_mark;
    i->chain = c->chain_name;
    i->device = c->device;
    return i;
}

static void iptables_find(
        struct node *head,
        const struct sockaddr *eth,
        const struct sockaddr_in *in,
        struct node **sip,
        struct node **smac)
{
    struct node *p;

    *sip = NULL;
    *smac = NULL;
    for (p = head; p; p = p->next) {
        if (memcmp(&p->in.sin_addr, &in->sin_addr, 4) == 0) {
            *sip = p;
            if (*smac) {
                break;
            }
        }

        if (memcmp(&p->eth.sa_data, &eth->sa_data, IFHWADDRLEN) == 0) {
            *smac = p;
            if (*sip) {
                break;
            }
        }
    }
}

int iptables_verify(
        struct iptables *i,
        const struct sockaddr *eth,
        const struct sockaddr_in *in)
{
    struct node *smac;
    struct node *sip;

    pthread_mutex_lock(&i->mutex);
    iptables_find(i->allowed, eth, in, &sip, &smac);
    pthread_mutex_unlock(&i->mutex);

    if (!sip || sip != smac) {
        return -1;
    }

    return 0;
}

int iptables_allow(
        struct iptables *i,
        const struct sockaddr *eth,
        const struct sockaddr_in *in,
        int milliseconds)
{
    struct timeval now;
    struct node *smac;
    struct node *sip;
    int64_t deadline;
    struct node *n;
    int ret;

    gettimeofday(&now, NULL);
    deadline = (int64_t)now.tv_sec * 1000000000 + (int64_t)now.tv_usec * 1000;
    deadline += (int64_t)milliseconds * 1000000;

    pthread_mutex_lock(&i->mutex);
    iptables_find(i->allowed, eth, in, &sip, &smac);

    ret = 0;
    if (sip && smac) {
        if (sip == smac) {
            /* Same user tries to extend its time */
            sip->deadline = deadline;

        } else {
            /* DHCP renewed and got a reused IP */
            ret |= iptables_delete(i, &smac->eth, &smac->in);
            ret |= iptables_delete(i, &sip->eth, &sip->in);
            ret |= iptables_insert(i, eth, in);
            iptables_node_remove(i, smac);
            sip->deadline = deadline;
            sip->eth = *eth;
        }

    } else if (sip) {
        /* DHCP released and allocated to another user */
        ret |= iptables_delete(i, &sip->eth, in);
        ret |= iptables_insert(i, eth, in);
        sip->deadline = deadline;
        sip->eth = *eth;

    } else if (smac) {
        /* DHCP renewed and got a new IP */
        ret |= iptables_delete(i, eth, &smac->in);
        ret |= iptables_insert(i, eth, in);
        smac->deadline = deadline;
        smac->in = *in;

    } else {
        /* New user */
        n = (struct node *)malloc(sizeof(struct node));
        memset(n, 0, sizeof(*n));
        n->deadline = deadline;
        n->eth = *eth;
        n->in = *in;
        iptables_node_add(i, n);
        ret |= iptables_insert(i, eth, in);
    }

    pthread_mutex_unlock(&i->mutex);
    return ret == 0 ? 0 : -1;
}

int iptables_deny(
        struct iptables *i,
        const struct sockaddr *eth,
        const struct sockaddr_in *in)
{
    struct node *smac;
    struct node *sip;
    int ret;

    pthread_mutex_lock(&i->mutex);
    iptables_find(i->allowed, eth, in, &sip, &smac);

    ret = 0;
    if (sip) {
        ret |= iptables_delete(i, &sip->eth, &sip->in);
        iptables_node_remove(i, sip);
        free(sip);
    }

    if (smac && smac != sip) {
        ret |= iptables_delete(i, &smac->eth, &smac->in);
        iptables_node_remove(i, smac);
        free(smac);
    }

    pthread_mutex_unlock(&i->mutex);
    return ret == 0 ? 0 : -1;
}

void iptables_cleanup(struct iptables *i)
{
    struct timeval tv;
    struct node *p;
    struct node *q;
    int64_t now;

    gettimeofday(&tv, NULL);
    now = (int64_t)tv.tv_sec * 1000000000 + (int64_t)tv.tv_usec * 1000;

    pthread_mutex_lock(&i->mutex);
    for (p = i->allowed; p;) {
        if (p->deadline > now) {
            p = p->next;
            continue;
        }

        iptables_node_remove(i, p);
        iptables_delete(i, &p->eth, &p->in);

        q = p;
        p = p->next;
        free(q);
    }
    pthread_mutex_unlock(&i->mutex);
}
