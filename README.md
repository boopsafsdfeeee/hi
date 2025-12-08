# 환경 변수 설정 (사용자의 환경에 맞게 수정 필수)
$VPN_ADAPTER_NAME = "VPN"             # SoftEther VPN 어댑터의 실제 이름
$DEFAULT_GW = "192.168.1.2"           # VM의 기본 게이트웨이 IP
$VPN_SERVER_IP = "12.34.56.78"        # SoftEther VPN 서버의 공인 IP

# --- 킬 스위치 활성화 (Kill-On.bat 역할) ---

Write-Host "VPN 서버 ($VPN_SERVER_IP) 경로 추가..." -ForegroundColor Green
# VPN 서버로 향하는 경로만 기본 게이트웨이를 통해 나가도록 설정
route add $VPN_SERVER_IP MASK 255.255.255.255 $DEFAULT_GW METRIC 1 | Out-Null

Write-Host "기본 게이트웨이 ($DEFAULT_GW) 경로 삭제 (킬 스위치 활성화)..." -ForegroundColor Red
# 인터넷으로 향하는 기본 경로 삭제
route delete 0.0.0.0 $DEFAULT_GW | Out-Null

# --- VPN 연결 감지 및 복구 루프 시작 ---

while ($true) {
    # VPN 어댑터의 상태를 확인
    $VPNStatus = Get-NetAdapter -Name $VPN_ADAPTER_NAME -ErrorAction SilentlyContinue

    if ($VPNStatus -and $VPNStatus.Status -eq "Up") {
        # VPN이 연결된 상태
        Write-Host "VPN 연결 감지: '$VPN_ADAPTER_NAME' - 상태: $($VPNStatus.Status)" -ForegroundColor Cyan
    } else {
        # VPN 연결이 끊어진 상태 (킬 스위치 복구)
        Write-Host "VPN 연결 끊김 감지! 킬 스위치 복구 시작..." -ForegroundColor Yellow

        # 1단계: VPN 서버 경로 제거 (선택 사항)
        Write-Host "VPN 서버 경로 제거 중..."
        route delete $VPN_SERVER_IP $DEFAULT_GW | Out-Null

        # 2단계: 기본 경로 복구 (인터넷 접근 재개)
        Write-Host "기본 게이트웨이 경로 복구 중..." -ForegroundColor Green
        route add 0.0.0.0 MASK 0.0.0.0 $DEFAULT_GW METRIC 20 | Out-Null
        
        Write-Host "킬 스위치 복구 완료. 스크립트를 종료합니다." -ForegroundColor Green
        break # 루프 종료
    }
    
    # 5초 간격으로 반복 검사
    Start-Sleep -Seconds 5
}
