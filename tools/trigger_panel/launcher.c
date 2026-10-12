/* Starts the Python runtime shipped inside this .app. No system Python is used. */
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void show_dialog(const char *message) {
    char command[4096];
    snprintf(
        command,
        sizeof(command),
        "osascript -e 'display dialog \"%s\" buttons {\"OK\"} default button 1 "
        "with title \"EDAMAME Trigger Panel\"'",
        message);
    system(command);
}

static int resources_dir(char *resources, size_t resources_len) {
    char executable[PATH_MAX];
    uint32_t size = sizeof(executable);
    char executable_copy[PATH_MAX];
    char *macos_dir;
    char relative[PATH_MAX];

    if (_NSGetExecutablePath(executable, &size) != 0) {
        return -1;
    }
    strncpy(executable_copy, executable, sizeof(executable_copy) - 1);
    executable_copy[sizeof(executable_copy) - 1] = '\0';
    macos_dir = dirname(executable_copy);
    snprintf(relative, sizeof(relative), "%s/../Resources", macos_dir);
    if (!realpath(relative, resources) || strlen(resources) >= resources_len) {
        return -1;
    }
    return 0;
}

static int run_python(const char *python, char *const argv[]) {
    pid_t child = fork();
    int status = 0;

    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        execv(python, argv);
        _exit(127);
    }
    if (waitpid(child, &status, 0) < 0) {
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

int main(void) {
    char resources[PATH_MAX];
    char python[PATH_MAX];
    char script[PATH_MAX];
    char triggers[PATH_MAX];
    char tcl_library[PATH_MAX];
    char tk_library[PATH_MAX];
    char *check_argv[4];
    char *app_argv[3];
    int check_status;

    if (resources_dir(resources, sizeof(resources)) != 0) {
        show_dialog("Could not find the files inside this app.");
        return 1;
    }

    snprintf(python, sizeof(python), "%s/python/bin/python3.11", resources);
    snprintf(script, sizeof(script), "%s/app.py", resources);
    snprintf(triggers, sizeof(triggers), "%s/triggers", resources);
    snprintf(tcl_library, sizeof(tcl_library), "%s/python/lib/tcl9.0", resources);
    snprintf(tk_library, sizeof(tk_library), "%s/python/lib/tk9.0", resources);

    if (access(python, X_OK) != 0 || access(script, R_OK) != 0) {
        show_dialog(
            "The Python runtime shipped inside this app is missing. "
            "You do not need to install Python. Download the app again.");
        return 1;
    }

    setenv("EDAMAME_TRIGGERS_DIR", triggers, 1);
    setenv("TCL_LIBRARY", tcl_library, 1);
    setenv("TK_LIBRARY", tk_library, 1);
    setenv("PYTHONNOUSERSITE", "1", 1);

    check_argv[0] = python;
    check_argv[1] = "-c";
    check_argv[2] = "import tkinter";
    check_argv[3] = NULL;
    check_status = run_python(python, check_argv);
    if (check_status != 0) {
        show_dialog(
            "This app includes Python and does not need one installed. "
            "macOS blocked the built-in runtime. Right-click the app and choose Open.");
        return 1;
    }

    if (getenv("EDAMAME_TRIGGER_PANEL_CHECK") != NULL) {
        return 0;
    }

    app_argv[0] = python;
    app_argv[1] = script;
    app_argv[2] = NULL;
    execv(python, app_argv);
    show_dialog("Could not start the built-in Python runtime.");
    return 1;
}
