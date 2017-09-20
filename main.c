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

#include <signal.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "configure.h"
#include "httpd.h"
#include "iptables.h"

static volatile sig_atomic_t g_quit;

static void on_signal_quit(int signum)
{
    (void)signum;
    g_quit = 1;
}

static int initialize_signals(void)
{
    struct sigaction sa;
    int i;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    for (i = 1; i < NSIG; ++i) {
        sigaction(i, &sa, NULL);
    }

    sa.sa_handler = on_signal_quit;
    if (sigaction(SIGHUP , &sa, NULL) ||
        sigaction(SIGINT , &sa, NULL) ||
        sigaction(SIGQUIT, &sa, NULL) ||
        sigaction(SIGTERM, &sa, NULL) ){

        return -1;
    }

    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL)) {
        return -1;
    }

    return 0;
}

static int check_device(const char *device)
{
    struct ifaddrs *ifa;
    struct ifaddrs *p;

    if (getifaddrs(&ifa)) {
        return -1;
    }

    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr) {
            continue;
        }

        if (p->ifa_addr->sa_family == AF_INET &&
            strcmp(p->ifa_name, device) == 0  ){

            freeifaddrs(ifa);
            return 0;
        }
    }

    freeifaddrs(ifa);
    return -1;
}

int main(int argc, char *argv[])
{
    struct configure *c;
    struct iptables *i;
    struct timespec tv;
    struct httpd *h;

    if (argc != 2) {
        fprintf(stderr, "%s <config filename>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (initialize_signals()) {
        return EXIT_FAILURE;
    }

    c = configure_load(argv[1]);
    if (!c) {
        fprintf(stderr, "Failed to parse configure file\n");
        return EXIT_FAILURE;
    }

    if (!c->device || check_device(c->device)) {
        fprintf(stderr, "Device [%s] doesn't exist\n", c->device);
        configure_free(c);
        return EXIT_FAILURE;
    }

    i = iptables_start(c);
    if (!i) {
        fprintf(stderr, "Failed to initialize iptables\n");
        configure_free(c);
        return EXIT_FAILURE;
    }

    h = httpd_start(c, i);
    if (!h) {
        fprintf(stderr, "Failed to initialize httpd\n");
        iptables_stop(i);
        configure_free(c);
        return EXIT_FAILURE;
    }

    memset(&tv, 0, sizeof(tv));
    tv.tv_nsec = 100000000;

    while (!g_quit) {
        nanosleep(&tv, NULL);
        iptables_cleanup(i);
    }

    httpd_stop(h);
    iptables_stop(i);
    configure_free(c);
    return EXIT_SUCCESS;
}
