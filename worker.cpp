#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <fstream>

using namespace std;

/* ===================== CONSTANTS ===================== */

static const string CG_BASE = "/sys/fs/cgroup/oj";
static const string CG_JOB  = "/sys/fs/cgroup/oj/job";

/* ===================== HELPERS ===================== */

void write_file(const string& path, const string& val) {
    int fd = open(path.c_str(), O_WRONLY | O_TRUNC);
    if (fd < 0) { perror(path.c_str()); _exit(1); }
    write(fd, val.c_str(), val.size());
    close(fd);
}

/* ===================== STEP 2: USER NAMESPACE ===================== */

void setup_user_namespace() {
    write_file("/proc/self/setgroups", "deny");
    write_file("/proc/self/uid_map", "0 1000 1"); // change if needed
    write_file("/proc/self/gid_map", "0 1000 1");
}

/* ===================== STEP 3: CGROUPS v2 ===================== */

void setup_cgroup_self() {
    mkdir(CG_BASE.c_str(), 0755); // ok if exists
    mkdir(CG_JOB.c_str(), 0755);  // per-job cgroup

    // Memory limit: 256 MB
    write_file(CG_JOB + "/memory.max", "268435456");

    // CPU limit: 1 core
    write_file(CG_JOB + "/cpu.max", "100000 100000");

    // Attach *current* process
    write_file(CG_JOB + "/cgroup.procs", "0");
}

bool memory_limit_hit() {
    ifstream f(CG_JOB + "/memory.events");
    string k; long v;
    while (f >> k >> v) {
        if (k == "max" && v > 0)
            return true;   // MLE
    }
    return false;
}

/* ===================== MAIN WORKER ===================== */

int main() {
    pid_t pid = fork();

    if (pid == 0) {
        /* -------- OUTER CHILD -------- */

        if (unshare(CLONE_NEWUSER | CLONE_NEWNS |
                    CLONE_NEWPID | CLONE_NEWNET) != 0) {
            perror("unshare");
            _exit(1);
        }

        setup_user_namespace();

        // Make mount namespace private
        mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr);

        pid_t inner = fork();
        if (inner == 0) {
            /* -------- PID 1 INSIDE SANDBOX -------- */

            /* STEP 1: BACKUP CPU LIMIT */
            rlimit cpu{2, 2}; // 2 seconds CPU
            setrlimit(RLIMIT_CPU, &cpu);

            /* STEP 3: CGROUP LIMITS */
            setup_cgroup_self();

            /* STEP 2: FILESYSTEM SANDBOX */
            mount("sandbox/root", "sandbox/root", nullptr,
                  MS_BIND | MS_REC, nullptr);
            chdir("sandbox/root");
            chroot(".");
            chdir("/");

            execl("/bin/a.out", "a.out", (char*)NULL);
            perror("exec");
            _exit(1);
        }

        int status;
        waitpid(inner, &status, 0);

        /* ================= VERDICT ================= */

        bool mle = memory_limit_hit();

        if (mle) {
            cout << "Verdict: MLE\n";
        }
        else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == SIGKILL || sig == SIGXCPU)
                cout << "Verdict: TLE\n";
            else
                cout << "Verdict: RE\n";
        }
        else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            cout << "Verdict: AC\n";
        }
        else {
            cout << "Verdict: RE\n";
        }

        _exit(0);
    }

    waitpid(pid, nullptr, 0);
    return 0;
}
