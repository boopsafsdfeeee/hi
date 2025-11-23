#include <windows.h>
#include <stdio.h>

#define RUNONCE_KEY L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
#define TARGET_NAME L"one"
#define TARGET_PATH L"C:\\Users\\user01\\AppData\\Roaming\\Project2.exe" // Target.exe 경로

BOOL RegisterRunOnce(LPCWSTR targetName, LPCWSTR targetPath) {
    HKEY hKey = NULL;
    LONG result;

    // 1. RunOnce 키 열기 (HKCU는 관리자 권한 불필요)
    result = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        RUNONCE_KEY,
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        wprintf(L"[-] RunOnce 키 열기 실패. Error: %lu\n", result);
        return FALSE;
    }

    // 2. 값 설정 (경로 등록)
    // RunOnce는 경로에 따옴표가 필요하면 직접 포함해야 합니다.
    WCHAR szQuotedPath[MAX_PATH + 2];
    wsprintfW(szQuotedPath, L"\"%s\"", targetPath);

    result = RegSetValueExW(
        hKey,
        targetName,       // 등록할 이름 (한 번 실행 후 삭제됨)
        0,
        REG_SZ,
        (const BYTE*)szQuotedPath,
        (DWORD)(wcslen(szQuotedPath) * sizeof(WCHAR)) + sizeof(WCHAR)
    );

    // 3. 키 닫기
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        wprintf(L"[+] RunOnce success.\n");
        return TRUE;
    }
    else {
        wprintf(L"[-] RunOnce 값 설정 실패. Error: %lu\n", result);
        return FALSE;
    }
}

int wmain() {
    RegisterRunOnce(TARGET_NAME, TARGET_PATH);
    return 0;
}
