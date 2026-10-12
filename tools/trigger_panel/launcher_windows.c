/* Starts the Python runtime shipped beside this launcher. No system Python is
 * used. GUI subsystem: launching pythonw.exe shows no console window.
 *
 * Layout (beside the launcher .exe):
 *   EDAMAME Trigger Panel.exe   <- this launcher
 *   app.py
 *   python\pythonw.exe          <- bundled standalone CPython
 *   triggers\                   <- copy of tests/security/triggers
 */
#include <windows.h>
#include <shlwapi.h>

static void show_dialog(const wchar_t *message) {
    MessageBoxW(NULL, message, L"EDAMAME Trigger Panel", MB_OK | MB_ICONERROR);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    PWSTR pCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)pCmdLine;
    (void)nCmdShow;

    wchar_t exe_path[MAX_PATH];
    wchar_t base_dir[MAX_PATH];
    wchar_t pythonw[MAX_PATH];
    wchar_t script[MAX_PATH];
    wchar_t triggers[MAX_PATH];
    wchar_t command[MAX_PATH * 3];

    if (GetModuleFileNameW(NULL, exe_path, MAX_PATH) == 0) {
        show_dialog(L"Could not locate the application files.");
        return 1;
    }
    /* base_dir = directory containing the launcher */
    lstrcpynW(base_dir, exe_path, MAX_PATH);
    PathRemoveFileSpecW(base_dir);

    /* pythonw = base_dir\python\pythonw.exe */
    lstrcpynW(pythonw, base_dir, MAX_PATH);
    PathAppendW(pythonw, L"python\\pythonw.exe");

    lstrcpynW(script, base_dir, MAX_PATH);
    PathAppendW(script, L"app.py");

    lstrcpynW(triggers, base_dir, MAX_PATH);
    PathAppendW(triggers, L"triggers");

    if (PathFileExistsW(pythonw) == FALSE || PathFileExistsW(script) == FALSE) {
        show_dialog(L"The Python runtime shipped inside this app is missing. "
                    L"You do not need to install Python. Download the app again.");
        return 1;
    }

    /* The child inherits this; app.py resolves the triggers directory from it. */
    SetEnvironmentVariableW(L"EDAMAME_TRIGGERS_DIR", triggers);
    SetEnvironmentVariableW(L"PYTHONNOUSERSITE", L"1");

    /* command line: "pythonw.exe" "app.py" */
    wsprintfW(command, L"\"%s\" \"%s\"", pythonw, script);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(pythonw, command, NULL, NULL, TRUE, 0, NULL, base_dir,
                        &si, &pi)) {
        show_dialog(L"Could not start the built-in Python runtime.");
        return 1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
