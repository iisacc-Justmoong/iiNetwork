# Network(L4) 로드 밸런서

iiNetwork 0.6.0의 `<iiNetwork/LoadBalancer.h>`는 IP 주소·포트·전송 종류에서 연결 키를
만들고 실제 백엔드 주소를 선택한다. 공통 대상 표·용량·건강·취소·드레이닝은 하위
iiSDKCore 0.19의 LoadBalancer/LoadLease를 조합한다. Core는 이 모듈을 참조하지 않으며
하위 Address/Transport/TLS도 이 오케스트레이션 계층을 역참조하지 않는다.

AWS의 [Network Load Balancer 연결 단위 라우팅](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/introduction.html)을
요구사항 참고로 삼았다. AWS의 비공개 해시와 wire/API 호환을 보장하지 않는다. DNS·VIP·
가용 영역 생성, 커널 패킷 프록시, 클라우드 리소스 자동 증설은 이 객체의 책임이 아니다.

## 연결 선택과 수평 분산

`NetworkFlow`는 TCP/UDP/TLS 종류와 source/destination `IpEndpoint`, 선택적인 TCP
initial_sequence를 가진다. 문자열 변환 없이 기존 IpAddress의 주소 바이트·주소군·IPv6
scope·포트를 해시한다. TCP/TLS는 sequence를 포함하고 UDP는 무시한다. sequence를
확보하지 않는 소켓 어댑터는 기본값 0을 사용한다. source와 destination의 주소군은 같아야
하고 destination port는 0일 수 없다. TCP/TLS source port도 0이면 거절한다.

`acquire(flow)`는 capacity 가중 rendezvous 해시로 접수 가능한 대상을 선택하고
`NetworkRoute { lease, backend }`를 반환한다. 동일 구성·그룹·키와 접수 상태에서는
같은 대상을 선택한다. 다른 대상의 접수 가능 상태가 유지될 때 대상 추가 시 새 대상이 이긴 키만 이동하며, 대상 제거 시 제거된
대상이 이겼던 키만 이동한다. 대상 식별자는 등록 수명 안에서 안정적이며 재시작/재등록을
넘는 영속 매핑은 아니다. capacity는 선언한 동시 작업량이며 CPU 측정이나 네트워크 속도가 아니다.

실제 TCP 연결/UDP flow를 만들 때 한 번 선택하고, 이후 패킷은 반환한 backend와 기존
연결을 계속 사용한다. 활성 flow의 lease는 대상 추가·건강 변경·드레이닝에도 대상을
바꾸지 않는다. 새로운 연결만 현재의 건강·용량·메모리·기능·그룹 조건에 따라 선택한다.
대상 선택 비용은 새 flow당 O(max_targets), 주소 해시 비용은 고정 길이이며, 별도의
전역 연결 맵이나 패킷별 재탐색을 만들지 않는다. 이미 확보한 backend 조회는 O(1)이다.
포화 대상은 새 연결 후보에서 제외한다. 키 해시는 암호학적 인증 수단이 아니며 외부
입력으로부터 패턴 예측을 줄이려면 호스트가 인스턴스별 hash_seed를 제공한다.

```cpp
ii::runtime::EventLoop loop;
ii::network::NetworkLoadBalancer routing;
auto target = routing.add_target(loop, backend_endpoint, {.capacity=128});
ii::network::NetworkFlow flow{
    .source = frontend_peer, .destination = frontend_local
};
auto selected = routing.acquire(flow);
if (selected) {
    ii::network::Tcp upstream(loop);
    auto connecting = upstream.connect(selected->backend);
    // loop에서 실제 연결·전송을 수행하고 결과를 관측한다.
    // 성공 응답과 스트림을 정리한 뒤:
    upstream.close();
    selected->lease.complete();
}
```

실행 가능한 loopback 예제는 `example/load_balancer.cpp`이다. 이 선택 객체가 소켓을
숨겨서 생성하거나 자동 프록시하는 것은 아니며 기존 Tcp/Udp/Tls 어댑터가 실제 연결을
소유한다. 소켓 조작과 콜백은 해당 EventLoop 소유 스레드에서 수행한다. 순수 선택·대상
등록은 인스턴스 잠금으로 보호된다. 대상 등록/주소 공개와 선택/주소 복사는 함께 처리한다.

## 수명과 운영

`report_health`의 연속 실패/성공 임계값, `request_drain`, 자원 접수 한도와 통계는
Core의 동일 계약을 따른다. 메모리와 기능은 `LoadRequest`로 신고한다. TLS 정책·세션 키·
실제 통신 성공은 별도 전송 객체가 검증하며 capability 비트만으로 입증되지 않는다.

전송 실패는 `lease.fail()`, 정상 종료는 실제 전송/버퍼 제거 후 `complete()`로 확정한다.
미완료 lease의 소멸은 취소이다. 연결 소유자는 lease.stop_token()을 관측하여 전송을
협력적으로 닫는다. 살아 있는 외부 lease 때문에 close/remove가 `would_block`이면
전송과 lease를 정리한 뒤 같은 종료 장벽을 다시 호출한다. 같은 연결 소유자가 자신을
기다리며 교착하지 않는다. `cancel_pending`은 모든 대상에 종료 요청을 전달한 뒤 대기한다.

UDP의 flow 만료 시점은 호스트가 결정하고 만료 때 lease를 반환한다. 이 모듈은 별도
타이머 스레드나 무제한 flow 캐시를 만들지 않는다. 등록 실행기는 성공한 대상 제거/전체
close까지 살아 있어야 한다. 후속 `lease.post`는 선택한 실행기로 전달하며 추가 연결로
세지 않는다. 실행기/대상 정리 중 거절한 작업은 다른 백엔드에 자동 재실행하지 않는다.

## 검사

`tests/load_balancer.cpp`는 IPv4/IPv6·TCP sequence·UDP 키, 동일 용량의 수평 분산,
1:3 용량 가중치, 새 대상에 한정한 키 이동, 기존 연결 고정, 건강·드레이닝·접수 한도와
종료 요청을 검사한다. 실제 네이티브 loopback TCP 스트림과 UDP 데이터그램을 선택한
백엔드로 전송한다. 설치 소비자도 같은 검사를 설치된 공개 헤더/라이브러리로 수행한다.
검증한 플랫폼과 결과는 `docs/Verification.md` 및 각 build/ 검증 기록으로 구분한다.

### 2026-10-25 검증 기록

| 범위 | 결과 |
|---|---|
| macOS arm64 Release 전체 빌드·CTest | 48/48 통과 |
| Core 0.19 + Network 0.6 설치 패키지 소비자 | 31/31 통과 |
| ASan/UBSan Network 로드 밸런서 | 1/1 통과 |
| TSan Network 로드 밸런서 | 1/1 통과, 경합 보고 없음 |
| 새 구현의 C++23 엄격 경고 | `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror` 통과 |
| Windows x64·Linux arm64·WASM32 pthread 새 구현 문법 검사 | 3/3 통과, 링크·대상 장치 실행은 별도 |

동일 용량의 두 대상에 1,024개 새 연결 키가 492/532로 분산되었고 세 번째 대상 추가 시
335개 키만 새 대상으로 이동했다. 기존 두 대상 사이의 불필요한 재매핑은 없었다.
실제 TCP 연결은 대상 드레이닝 후에도 같은 백엔드에서 두 payload를 수신했고, UDP도
선택한 실제 loopback 백엔드에서 두 데이터그램을 수신했다. 이는 macOS 로컬 소켓의
실행 증거이며 인터넷/WAN 성능, TLS 로드 밸런서 종료, 다른 OS 실기기 실행은 아니다.

리스너/전송 종류별 서비스가 다르면 대상의 `group`과 요청의 `group`을 분리한다.
프로토콜 키가 다르다는 이유만으로 백엔드의 지원 프로토콜을 자동 추정하지 않는다.
TLS는 flow 식별만 제공하며 암호화·인증 정책은 기존 TlsStream/TlsContext가 담당한다.

XML·sanitizer·설치 소비자 로그는 `build/load-routing-20261025/`, 설치 검증 패키지는
그 아래 `stage/iiNetwork`이다. 기본 설치본은 교체하지 않았다. 작업 전 존재한
Interfaces.md·Tls.cpp·TLS fixture/인터페이스 테스트 변경은 그대로 보존했다.
