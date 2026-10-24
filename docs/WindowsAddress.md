# Windows IPv6 scope 검증

이름으로 지정한 IPv6 scope는 Windows IP Helper의 `if_nametoindex`로 실제 인터페이스
인덱스에 대응한다. 해당 선언을 소유한 `iphlpapi.h`를 Address 구현에서 직접 포함한다.
Iphlpapi 링크는 기존 Windows 타깃 설정을 사용하며 public API에 OS 타입을 노출하지 않는다.
[Microsoft의 선언·링크 계약](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-if_nametoindex)을 따른다.

`iiNetwork.interfaces.address`는 실제 loopback의 인덱스와 OS 이름 변환을 사용하여
이름 scope와 숫자 scope가 같은 주소·scope 값을 만드는지 확인한다. 존재하지 않는
이름은 계속 거절한다. 외부 서버나 실제 네트워크 구성을 변경하지 않는다.

Windows ROOT 인증서 저장소를 여는 예약 인자는 정수 핸들 형식
`HCRYPTPROV_LEGACY`의 0을 사용한다. 포인터 nullptr와 혼동하여 MSVC 컴파일이
실패하지 않게 하며, 기본 TLS 클라이언트 context 생성으로 실제 시스템 신뢰
초기화 경로도 검사한다. 인증서를 추가하거나 시스템 저장소를 수정하지 않는다.

AF_UNIX의 Windows 파일 항목은 reparse point이므로 일반 파일처럼 따라가는
`std::filesystem::exists`가 `ERROR_CANT_ACCESS_FILE`을 반환할 수 있다. IPC 검사는
`GetFileAttributesW`로 항목 존재를 확인하고, 실제 소켓 왕복·소유 항목 정리·교체된
사용자 파일 보존을 그대로 검증한다.

HTTP graceful shutdown 검사는 500ms 유예 안에 이미 수락한 요청의 나머지 본문과
응답을 완료한다. Windows에서 수 초가 걸릴 수 있는 별도 연결의 거절 알림은 그 뒤
확인한다. 종료 시 새 연결 거절, 진행 중 응답 보존, 유예 만료 강제 종료 조건은 유지한다.
