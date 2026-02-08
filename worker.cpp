#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <cstring>
#include <sched.h>

using namespace std;

/* -------- helpers -------- */

void write_file(const string& path, const string& val) {
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) { perror(path.c_str()); _exit(1); }
    if (write(fd, val.c_str(), val.size()) < 0) {
        perror(("write failed: " + path).c_str());
        _exit(1);
    }
    close(fd);
}

/* -------- cgroup -------- */

string cg_job;

void setup_cgroup(pid_t pid) {
    cg_job = "/sys/fs/cgroup/oj/job_" + to_string(pid);
    rmdir(cg_job.c_str());
    mkdir(cg_job.c_str(), 0755);

    write_file(cg_job + "/memory.max", "268435456");   // 256MB
    write_file(cg_job + "/cpu.max", "100000 100000"); // 1 CPU
    write_file(cg_job + "/cgroup.procs", to_string(pid));
}

bool memory_limit_hit() {
    ifstream f(cg_job + "/memory.events");
    string k; long v;
    while (f >> k >> v)
        if (k == "max" && v > 0) return true;
    return false;
}

/* -------- uid/gid mapping (parent only) -------- */

void setup_uid_gid_map(pid_t pid) {
    string base = "/proc/" + to_string(pid);
    write_file(base + "/setgroups", "deny");
    write_file(base + "/uid_map", "0 1000 1");
    write_file(base + "/gid_map", "0 1000 1");
}

/* -------- main -------- */

int main() {
    int child_ready[2];
    int parent_done[2];
    pipe(child_ready);
    pipe(parent_done);

    pid_t child = fork();

    if (child == 0) {
        /* -------- CHILD -------- */
        close(child_ready[0]);
        close(parent_done[1]);

        // enter user + pid namespaces
        if (unshare(CLONE_NEWUSER | CLONE_NEWPID) != 0) {
            perror("unshare");
            _exit(1);
        }

        // notify parent
        write(child_ready[1], "x", 1);
        close(child_ready[1]);

        // wait for uid/gid map
        char dummy;
        read(parent_done[0], &dummy, 1);
        close(parent_done[0]);

        pid_t inner = fork();
        if (inner == 0) {
            /* -------- PID 1 -------- */

            // CPU limit
            rlimit cpu{2,2};
            setrlimit(RLIMIT_CPU, &cpu);

            // 🔑 STOP mount propagation (FIXES LEAK)
            mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr);

            // filesystem jail
            mount("sandbox/root", "sandbox/root", nullptr, MS_BIND | MS_REC, nullptr);
            chdir("sandbox/root");
            chroot(".");
            chdir("/");

            execl("/bin/a.out", "a.out", nullptr);
            _exit(1);
        }

        int st;
        waitpid(inner, &st, 0);

        // 🔑 propagate signal correctly (TLE fix)
        if (WIFSIGNALED(st)) {
            kill(getpid(), WTERMSIG(st));
        }

        _exit(WEXITSTATUS(st));
    }

    /* -------- PARENT -------- */
    close(child_ready[1]);
    close(parent_done[0]);

    // wait for user namespace creation
    char dummy;
    read(child_ready[0], &dummy, 1);
    close(child_ready[0]);

    setup_cgroup(child);
    setup_uid_gid_map(child);

    // let child continue
    write(parent_done[1], "x", 1);
    close(parent_done[1]);

    int status;
    waitpid(child, &status, 0);

    if (memory_limit_hit()) cout << "Verdict: MLE\n";
    else if (WIFSIGNALED(status)) cout << "Verdict: TLE\n";
    else if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        cout << "Verdict: AC\n";
    else cout << "Verdict: RE\n";

    rmdir(cg_job.c_str());
    return 0;
}
