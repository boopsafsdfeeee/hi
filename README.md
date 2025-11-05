# hi

[base64.h]

#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

// Base64 인코딩 함수 (입력 데이터 → Base64 문자열)
char* base64_encode(const unsigned char* data, size_t len, size_t* out_len);

// Base64 디코딩 함수 (Base64 문자열 → 원래 데이터)
unsigned char* base64_decode(const char* data, size_t len, size_t* out_len);

#endif


[base64.c]
#include "base64.h"
#include <stdlib.h>

static const char b64_table[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const unsigned char* data, size_t len, size_t* out_len) {
    size_t olen = 4 * ((len + 2) / 3);
    char* out = (char*)malloc(olen + 1);
    if (!out) return NULL;

    size_t i = 0, j = 0;
    while (i < len) {
        unsigned octet_a = i < len ? data[i++] : 0;
        unsigned octet_b = i < len ? data[i++] : 0;
        unsigned octet_c = i < len ? data[i++] : 0;

        unsigned triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = b64_table[(triple >> 18) & 63];
        out[j++] = b64_table[(triple >> 12) & 63];
        out[j++] = (i > len + 1) ? '=' : b64_table[(triple >> 6) & 63];
        out[j++] = (i > len)     ? '=' : b64_table[triple & 63];
    }

    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

unsigned char* base64_decode(const char* data, size_t len, size_t* out_len) {
    if (len % 4 != 0) return NULL;

    size_t olen = len / 4 * 3;
    if (data[len - 1] == '=') olen--;
    if (data[len - 2] == '=') olen--;

    unsigned char* out = (unsigned char*)malloc(olen + 1);
    if (!out) return NULL;

    unsigned buffer = 0;
    int bits = 0;
    size_t j = 0;

    for (size_t i = 0; i < len; i++) {
        char c = data[i];
        int val;

        if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
        else if (c >= '0' && c <= '9') val = c - '0' + 52;
        else if (c == '+') val = 62;
        else if (c == '/') val = 63;
        else if (c == '=') { buffer <<= 6; bits += 6; continue; }
        else continue;

        buffer = (buffer << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            out[j++] = (buffer >> bits) & 0xFF;
        }
    }

    out[j] = '\0';
    if (*out_len) *out_len = j;
    return out;
}


[client]

#include <stdio.h>              // printf 사용
#include <stdlib.h>             // malloc, free 사용
#include <string.h>             // memcpy, strlen 사용
#include <stdint.h>             // 고정폭 정수 사용 (uint8_t 등)
#include <time.h>               // 난수 시드 설정용
#include <winsock2.h>           // WinSock 네트워크 API
#include <ws2tcpip.h>           // inet_pton 사용
#include "base64.h"             // Base64 모듈 헤더 포함
#pragma comment(lib, "ws2_32.lib") // WinSock 라이브러리 링크 지정

#define BUF_SIZE 4096           // 전송 버퍼 크기 정의

// DNS 헤더 구조체 (네트워크 전송 시 정확한 크기 유지를 위해 1바이트 패킹)
#pragma pack(push,1)
typedef struct dns_header {
    uint16_t id;                // 트랜잭션 ID
    uint16_t flags;             // 플래그 (쿼리/응답 등)
    uint16_t qdcount;           // 질문 섹션 개수
    uint16_t ancount;           // 응답 섹션 개수
    uint16_t nscount;           // 권한 섹션 개수
    uint16_t arcount;           // 추가 섹션 개수
} dns_header;
#pragma pack(pop)

// 질문 꼬리 (QTYPE + QCLASS) 구조체
#pragma pack(push,1)
typedef struct qtail { uint16_t qtype, qclass; } qtail;
#pragma pack(pop)

// "example.com" → DNS 라벨 형식으로 변환하는 함수
static int write_qname(uint8_t* buf, size_t buflen, const char* name) {
    size_t bi = 0;              // 출력 위치
    const char* start = name;   // 라벨 시작 위치
    size_t len = 0;             // 라벨 길이

    while (1) {
        if (*name == '.' || *name == '\0') {
            buf[bi++] = (uint8_t)len;         // 라벨 길이 기록
            memcpy(buf + bi, start, len);     // 라벨 문자 복사
            bi += len;
            if (*name == '\0') break;         // 문자열 끝이면 종료
            name++;                            // '.' 건너뛰고 다음 라벨로
            start = name;                      // 새 라벨 시작
            len = 0;                           // 라벨 길이 초기화
        }
        else {
            len++;                             // 라벨 문자 수 증가
            name++;                            // 다음 문자로
        }
    }
    buf[bi++] = 0;              // 라벨 종료 (0 바이트)
    return (int)bi;             // 총 기록된 바이트 수 반환
}

int main(int argc, char** argv) {

    if (argc < 4) {                                                 // 인자 부족시 사용법 출력
        printf("Usage: %s <server_ip> <domain> <text> [port]\n", argv[0]);
        return 1;
    }

    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);                  // WinSock 초기화

    const char* server_ip = argv[1];                               // 서버 IP
    const char* domain = argv[2];                                  // 조회 도메인
    const char* text = argv[3];                                    // 보낼 평문 문자열
    int port = (argc >= 5) ? atoi(argv[4]) : 5300;                 // 포트 (기본값 5300)

    size_t b64_len;                                                // Base64 길이 저장 변수
    char* encoded = base64_encode((const unsigned char*)text, strlen(text), &b64_len); // Base64 인코딩 수행

    uint8_t buf[BUF_SIZE] = { 0 };                                 // DNS 패킷 버퍼
    dns_header* h = (dns_header*)buf;                              // 헤더 위치 지정

    h->id = htons(rand() & 0xFFFF);                                // 랜덤 TXID
    h->flags = htons(0x0100);                                      // 표준 질의
    h->qdcount = htons(1);                                         // 질문 1개
    h->arcount = htons(1);                                         // Additional 섹션 1개사용 (TXT 데이터 삽입)

    size_t off = sizeof(dns_header);                               // 헤더 다음부터 쓰기 시작
    off += write_qname(buf + off, BUF_SIZE - off, domain);         // QNAME 기록

    qtail* qt = (qtail*)(buf + off);                               // 질문 꼬리 위치
    qt->qtype = htons(1);                                          // QTYPE = A
    qt->qclass = htons(1);                                         // QCLASS = IN
    off += sizeof(*qt);

    buf[off++] = 0;                                                // Additional RR 이름 = 루트
    buf[off++] = 0x00; buf[off++] = 0x10;                           // TYPE = TXT
    buf[off++] = 0x00; buf[off++] = 0x01;                           // CLASS = IN
    buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; // TTL = 0

    size_t rdlen_pos = off;                                        // RDLENGTH 위치 기록
    off += 2;                                                      // RDLENGTH 나중에 채움

    buf[off++] = (uint8_t)b64_len;                                 // TXT 길이
    memcpy(buf + off, encoded, b64_len);                            // Base64 문자열 삽입
    off += b64_len;

    uint16_t rdlen = (uint16_t)(1 + b64_len);                      // 길이 계산
    buf[rdlen_pos] = rdlen >> 8;
    buf[rdlen_pos + 1] = rdlen & 0xFF;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);                      // UDP 소켓 생성
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &dst.sin_addr);                   // 문자열 IP → 바이너리 변환

    sendto(s, (char*)buf, (int)off, 0, (struct sockaddr*)&dst, sizeof(dst)); // DNS 패킷 전송

    printf("[Client] Sent Base64: %s\n", encoded);                  // 전송한 Base64 출력

    closesocket(s);                                                 // 소켓 종료
    free(encoded);                                                  // Base64 메모리 해제
    WSACleanup();                                                   // WinSock 종료

    return 0;
}


[server]

// ---------------------------------------------
// dns_server.c  (Base64 모듈 분리판, 모든 줄 주석)
// ---------------------------------------------

#include <stdio.h>              // printf 등 표준 입출력 함수 사용
#include <stdlib.h>             // malloc/free, atoi 등 표준 라이브러리
#include <string.h>             // memcpy, memset, strlen 등 메모리/문자열 함수
#include <stdint.h>             // 고정 폭 정수 타입(uint8_t, uint16_t 등)
#include <time.h>               // time(), localtime() 등 시간 관련
#include <winsock2.h>           // Windows 소켓 API (socket, bind, sendto 등)
#include <ws2tcpip.h>           // inet_pton 등 추가 네트워킹 유틸
#include "base64.h"             // 분리된 Base64 모듈 헤더 포함
#pragma comment(lib, "ws2_32.lib") // Visual Studio에서 ws2_32.lib 자동 링크

#define BUF_SIZE 4096           // 수신/송신 버퍼 최대 크기 정의

// ----- DNS 헤더 구조체 (네트워크 전송 포맷과 정확히 맞추기 위해 1바이트 패킹) -----
#pragma pack(push,1)            // 구조체 패딩을 1바이트로 고정
typedef struct dns_header {
    uint16_t id;                // 트랜잭션 ID (클라이언트와 동일하게 맞춰야 함)
    uint16_t flags;             // 플래그(쿼리/응답, AA, TC, RD, RA, RCODE 등)
    uint16_t qdcount;           // Question 섹션 개수
    uint16_t ancount;           // Answer 섹션 개수
    uint16_t nscount;           // Authority 섹션 개수
    uint16_t arcount;           // Additional 섹션 개수
} dns_header;
#pragma pack(pop)               // 패킹 설정 원복

// ----- QNAME 스킵 함수 (도메인 라벨 형식 이름을 한 개 건너뛰고 소비한 바이트 수 반환) -----
static int skip_qname(const uint8_t* buf, size_t buflen) { // buf: 시작 위치, buflen: 남은 길이
    size_t i = 0;                                         // 현재 탐색 위치
    while (i < buflen) {                                  // 버퍼 끝까지 확인
        uint8_t len = buf[i++];                           // 라벨 길이 바이트 획득
        if (len == 0) return (int)i;                      // 0이면 루트라벨 → QNAME 종료, 소비 길이 반환
        if (len & 0xC0) {                                 // 0xC0 마스크면 압축 포인터(11xxxxxx) 의미
            if (i >= buflen) return -1;                   // 포인터는 2바이트 필요, 범위를 벗어나면 에러
            return (int)(i + 1);                          // 포인터(2바이트)까지 소비한 길이 반환
        }
        if (i + len > buflen) return -1;                  // 라벨 실제 길이가 버퍼를 넘으면 에러
        i += len;                                         // 라벨 문자열 부분 건너뛰기
    }
    return -1;                                            // 끝까지 갔는데도 종료 못하면 에러
}

int main(int argc, char** argv) {                         // 프로그램 진입점
    int port = (argc >= 2) ? atoi(argv[1]) : 5300;        // 첫 인자가 있으면 포트로 사용, 없으면 기본 5300

    WSADATA wsa;                                          // WinSock 초기화를 위한 구조체
    WSAStartup(MAKEWORD(2, 2), &wsa);                     // WinSock 버전 2.2 초기화

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);            // UDP 소켓 생성
    if (s == INVALID_SOCKET) {                            // 소켓 생성 실패 여부 확인
        printf("[Server] socket() failed: %d\n", WSAGetLastError()); // 오류 출력
        WSACleanup();                                     // WinSock 정리
        return 1;                                         // 비정상 종료
    }

    struct sockaddr_in srv;                               // 서버(바인딩) 주소 구조체
    memset(&srv, 0, sizeof(srv));                         // 구조체를 0으로 초기화
    srv.sin_family = AF_INET;                             // 주소 체계 = IPv4
    srv.sin_port = htons((u_short)port);                  // 포트(네트워크 바이트 오더)
    srv.sin_addr.s_addr = htonl(INADDR_ANY);              // 모든 인터페이스에서 수신

    if (bind(s, (struct sockaddr*)&srv, sizeof(srv)) == SOCKET_ERROR) { // 바인드 시도
        printf("[Server] bind() failed: %d\n", WSAGetLastError());      // 실패 시 오류 출력
        closesocket(s);                                 // 소켓 닫기
        WSACleanup();                                   // WinSock 정리
        return 1;                                       // 종료
    }

    printf("[Server] Started on UDP %d\n", port);        // 서버 시작 로그 출력

    uint8_t buf[BUF_SIZE];                               // 수신 패킷 버퍼

    for (;;) {                                           // 무한 루프 (서버 계속 동작)
        struct sockaddr_in cli;                          // 클라이언트(송신자) 주소 저장 구조체
        int clen = sizeof(cli);                          // 주소 길이 변수
        int n = recvfrom(s, (char*)buf, BUF_SIZE, 0, (struct sockaddr*)&cli, &clen); // UDP 패킷 수신
        if (n <= 0) continue;                            // 수신 실패/0바이트면 다음 루프로

        if ((size_t)n < sizeof(dns_header)) {            // DNS 헤더보다 짧으면 잘못된 패킷
            printf("[Server] too short for DNS header\n"); // 경고 출력
            continue;                                    // 무시
        }

        dns_header* reqh = (dns_header*)buf;             // 수신 버퍼의 시작을 DNS 헤더로 해석
        size_t off = sizeof(dns_header);                 // 오프셋을 DNS 헤더 다음으로 위치시킴

        int qname_len = skip_qname(buf + off, n - off);  // 질문(QNAME) 길이 계산
        if (qname_len < 0 || off + qname_len + 4 > (size_t)n) { // QNAME + QTYPE/QCLASS 4바이트가 있는지 검사
            printf("[Server] malformed question\n");     // 형식 오류
            continue;                                    // 무시
        }

        const uint8_t* qname_ptr = buf + off;            // 질문 도메인(QNAME) 시작 주소 저장 (응답에 재사용)
        off += qname_len;                                 // 오프셋을 QTYPE/QCLASS 위치로 이동
        const uint8_t* qtail = buf + off;                // QTYPE/QCLASS 4바이트 포인터 저장
        off += 4;                                        // 오프셋을 다음 섹션으로 이동

        // 이제 Additional 섹션(클라이언트가 보낸 Base64-텍스트가 들어있는 TXT RR)을 기대함
        if (off + 1 + 2 + 2 + 4 + 2 > (size_t)n) {       // NAME(최소 1) + TYPE2 + CLASS2 + TTL4 + RDLEN2 존재 확인
            printf("[Server] no additional RR\n");       // 추가 섹션 없으면 처리 불가
            continue;                                    // 무시
        }

        // 추가 RR의 NAME 처리: 우리 클라 구현은 root(0x00)이지만, 혹시 모를 일반 QNAME도 허용
        int name_bytes = 0;                              // NAME이 소비한 바이트 수
        if (buf[off] == 0x00) {                          // 첫 바이트가 0x00이면 root 라벨
            name_bytes = 1;                              // NAME은 1바이트 소비
        } else {                                         // 그 외에는 일반 QNAME 또는 포인터로 간주
            int sbytes = skip_qname(buf + off, n - off); // QNAME 스킵 시도
            if (sbytes < 0) {                            // 실패 시
                printf("[Server] bad RR name\n");        // 경고
                continue;                                // 무시
            }
            name_bytes = sbytes;                         // 소비한 길이 기록
        }
        off += name_bytes;                               // 오프셋 이동

        // TYPE/CLASS/TTL/RDLEN 읽기 (TXT인지 확인)
        if (off + 10 > (size_t)n) {                      // 2+2+4+2 = 10바이트가 남아야 함
            printf("[Server] short RR header\n");        // 짧으면 에러
            continue;                                    // 무시
        }
        uint16_t rr_type  = (uint16_t)((buf[off] << 8) | buf[off+1]);  // TYPE big-endian
        off += 2;                                        // 오프셋 이동
        uint16_t rr_class = (uint16_t)((buf[off] << 8) | buf[off+1]);  // CLASS big-endian
        off += 2;                                        // 오프셋 이동
        uint32_t rr_ttl   = (uint32_t)((buf[off] << 24) | (buf[off+1] << 16) | (buf[off+2] << 8) | buf[off+3]); // TTL
        (void)rr_ttl;                                    // 여기서는 TTL 사용 안 함(경고 억제)
        off += 4;                                        // 오프셋 이동
        uint16_t rr_rdlen = (uint16_t)((buf[off] << 8) | buf[off+1]); // RDLENGTH
        off += 2;                                        // 오프셋 이동

        if (rr_type != 16 || rr_class != 1) {            // TYPE=TXT(16), CLASS=IN(1)인지 검사
            printf("[Server] not a TXT RR\n");           // 아니면 무시
            continue;                                    // 무시
        }
        if (off + rr_rdlen > (size_t)n) {                // RDATA 전체가 패킷 길이를 넘는지 검사
            printf("[Server] RDATA overflow\n");         // 넘치면 에러
            continue;                                    // 무시
        }
        if (rr_rdlen < 1) {                              // 최소 1바이트(TXT 첫 길이 바이트) 필요
            printf("[Server] bad TXT length\n");         // 에러
            continue;                                    // 무시
        }

        uint8_t L = buf[off];                            // TXT 첫 바이트 = 문자열 길이
        if ((size_t)(1 + L) > rr_rdlen) {                // 길이 바이트 + 데이터가 RDLEN을 넘는지 확인
            printf("[Server] bad TXT chunk len\n");      // 에러
            continue;                                    // 무시
        }
        if (L > 255) L = 255;                            // TXT 조각 길이는 최대 255

        char b64_in[256] = {0};                          // Base64 문자열을 임시 보관할 버퍼
        memcpy(b64_in, buf + off + 1, L);                // RDATA에서 실제 문자열 복사(길이 바이트 다음)
        // 이제 b64_in에 Base64로 인코딩된 클라이언트 텍스트가 들어있음

        size_t plain_len = 0;                            // 디코드된 평문 길이를 받을 변수
        unsigned char* plain = base64_decode(b64_in, L, &plain_len); // Base64 디코딩 수행
        if (!plain) {                                    // 디코딩 실패 시
            printf("[Server] base64 decode fail\n");     // 에러 출력
            continue;                                    // 무시
        }

        printf("[Server] Received base64='%s', text='%.*s'\n",
               b64_in, (int)plain_len, plain);          // 수신 내용 로그로 출력

        // ----- 간단한 명령 라우팅 (키워드 별 응답) -----
        char response[256] = {0};                        // 응답 평문을 담을 버퍼
        if (strstr((char*)plain, "hello")) {             // 수신 텍스트에 "hello" 포함?
            strcpy(response, "hi client!");              // -> "hi client!" 응답
        } else if (strstr((char*)plain, "time")) {       // "time" 포함?
            time_t t = time(NULL);                       // 현재 시간 초 얻기
            struct tm* tm = localtime(&t);               // 로컬 타임존 변환
            strftime(response, sizeof(response),         // 사람이 읽을 수 있는 포맷으로 변환
                     "time: %Y-%m-%d %H:%M:%S", tm);
        } else {                                         // 그 외 키워드는
            strcpy(response, "unknown");                 // "unknown" 응답
        }
        free(plain);                                     // 평문 메모리 해제

        // ----- 응답 평문을 Base64로 인코딩 -----
        size_t enc_len = 0;                              // 인코딩된 길이를 받을 변수
        char* b64_out = base64_encode((unsigned char*)response, strlen(response), &enc_len); // 인코딩 수행
        if (!b64_out) {                                  // 실패 시
            printf("[Server] base64 encode fail\n");     // 에러 출력
            continue;                                    // 무시
        }
        if (enc_len > 255) enc_len = 255;                // TXT 조각은 255바이트 제한

        // ----- DNS 응답 패킷 구성 -----
        uint8_t outbuf[BUF_SIZE];                        // 송신 버퍼
        memset(outbuf, 0, sizeof(outbuf));               // 버퍼 0으로 초기화
        dns_header* reph = (dns_header*)outbuf;          // 응답 헤더 포인터

        reph->id      = reqh->id;                        // 요청과 동일한 트랜잭션 ID 사용
        reph->flags   = htons(0x8180);                   // 표준 응답, RA=1, RCODE=0 (No error)
        reph->qdcount = htons(1);                        // Question 1개 (요청과 동일 구조)
        reph->ancount = htons(1);                        // Answer 1개 (TXT로 응답)
        reph->nscount = htons(0);                        // Authority 0
        reph->arcount = htons(0);                        // Additional 0 (응답에선 사용하지 않음)

        size_t roff = sizeof(dns_header);                // 헤더 뒤로 오프셋 이동

        // Question 섹션 그대로 복사 (QNAME + QTYPE/QCLASS)
        memcpy(outbuf + roff, qname_ptr, qname_len);     // QNAME 복사
        roff += qname_len;                               // 오프셋 증가
        memcpy(outbuf + roff, qtail, 4);                 // QTYPE/QCLASS 4바이트 복사
        roff += 4;                                       // 오프셋 증가

        // Answer 섹션 NAME: 압축 포인터로 QNAME(오프셋 0x000C) 참조 (0xC0 0x0C)
        outbuf[roff++] = 0xC0;                           // 압축 포인터 상위 바이트 (1100 0000)
        outbuf[roff++] = 0x0C;                           // QNAME 시작 위치(12)를 가리킴

        // TYPE=TXT(0x0010), CLASS=IN(0x0001)
        outbuf[roff++] = 0x00; outbuf[roff++] = 0x10;    // TYPE = TXT
        outbuf[roff++] = 0x00; outbuf[roff++] = 0x01;    // CLASS = IN

        // TTL = 30초 (0x0000001E)
        outbuf[roff++] = 0x00;                           // TTL 바이트 1
        outbuf[roff++] = 0x00;                           // TTL 바이트 2
        outbuf[roff++] = 0x00;                           // TTL 바이트 3
        outbuf[roff++] = 0x1E;                           // TTL 바이트 4 (=30)

        // RDLENGTH = 1(길이바이트) + enc_len
        uint16_t txt_rdlen = (uint16_t)(1 + enc_len);    // TXT 데이터 전체 길이
        outbuf[roff++] = (uint8_t)(txt_rdlen >> 8);      // 상위 바이트
        outbuf[roff++] = (uint8_t)(txt_rdlen & 0xFF);    // 하위 바이트

        // TXT 실제 데이터: [길이][Base64문자열...]
        outbuf[roff++] = (uint8_t)enc_len;               // 첫 바이트 = TXT 문자열 길이
        memcpy(outbuf + roff, b64_out, enc_len);         // Base64 문자열 복사
        roff += enc_len;                                  // 오프셋 증가

        // UDP로 응답 전송
        sendto(s, (const char*)outbuf, (int)roff, 0, (struct sockaddr*)&cli, clen); // 클라이언트 주소로 전송

        free(b64_out);                                    // Base64 인코딩 결과 메모리 해제
    }

    // (실행 중에는 도달하지 않음 - 서버 무한 루프)
    // closesocket(s); WSACleanup(); return 0;
}


-----
빌드 cl /O2 /W3 base64.c dns_server.c ws2_32.lib /Fe:dns_server.exe
.\Project20 127.0.0.1 test.com "hello" 9999


