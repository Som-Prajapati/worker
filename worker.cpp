#include <iostream>
#include <vector>
#include <algorithm>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

using namespace std;

pid_t child_pid = -1; // Global so signal handler can see it

struct Result {
    string verdict;
    int exitCode;
    int signal;
};

// If the wall-clock hits the limit, the Parent runs this
void watchdog_handler(int sig) {
    if (child_pid > 0) {
        kill(child_pid, SIGKILL); // Execute the prisoner
    }
}

void apply_limits() {
    rlimit cpu{2, 2}; // 2s CPU
    setrlimit(RLIMIT_CPU, &cpu);

    rlimit mem{256 * 1024 * 1024, 256 * 1024 * 1024}; // 256MB
    setrlimit(RLIMIT_AS, &mem);

    rlimit nproc{10, 10}; // No fork bombs
    setrlimit(RLIMIT_NPROC, &nproc);
}


string classify(int status) {
  if (WIFEXITED(status)) {
      int code = WEXITSTATUS(status);
      return (code == 0) ? "AC" : "RE";
  }

  if (WIFSIGNALED(status)) {
      int sig = WTERMSIG(status);

      switch (sig) {
          case SIGXCPU:
              return "TLE";
          case SIGKILL:
              // TEMPORARY: ambiguous without cgroups
              return "TLE_OR_MLE";
          case SIGSEGV:
          case SIGABRT:
          case SIGFPE:
          case SIGILL:
              return "RE";
          default:
              return "RE";
      }
  }

  return "RE";
}

Result run_program() {
    // 1. Setup Watchdog
    signal(SIGALRM, watchdog_handler);
    alarm(3); // Wall-clock limit: 3 seconds

    child_pid = fork();

    if (child_pid == 0) {
        apply_limits();
        // Setup IO and Exec as before...
        execl("./sandbox/run/a.out", "./a.out", (char*)NULL);
        _exit(1);
    }

    int status;
    waitpid(child_pid, &status, 0);
    
    // 2. Cancel Watchdog
    alarm(0); 

    Result res;
    res.verdict = classify(status);
    if (WIFEXITED(status)) { res.exitCode = WEXITSTATUS(status); res.signal = 0; }
    else { res.exitCode = -1; res.signal = WTERMSIG(status); }
    return res;
}

int main() {
    Result r = run_program();
    cout << "Verdict: " << r.verdict << " (Signal: " << r.signal << ")" << endl;
    return 0;
}