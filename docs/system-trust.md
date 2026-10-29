# 재배치 가능한 TLS 신뢰 저장소

명시적인 CA 파일·디렉터리 또는 인증서 pin이 없는 TLS 검증은 OS의 기본 루트 인증서를 사용한다. macOS는 Security의 anchor 인증서, Windows는 ROOT 인증서 저장소, Linux는 배포판의 표준 CA 번들을 OpenSSL 검증기에 제공한다. 빌드 시 OpenSSL prefix나 Homebrew 설치 경로의 인증서 파일에 의존하지 않는다.

iPadOS는 루트 인증서 내보내기 API를 제공하지 않으므로 OpenSSL의 기본 체인 검증 콜백에서 Security의 SecTrust를 사용한다. 제공된 인증서 체인과 SSL 서버/클라이언트 용도, 호스트명/IP 및 깊이를 검증하며 실패를 허용으로 바꾸지 않는다. Core 이벤트 루프에서 숨은 동기 네트워크 조회를 하지 않도록 중간 인증서 자동 다운로드를 끈다. 명시적 CA·pin 경로는 이 기본 콜백을 설치하지 않는다. HTTP 소비자의 iPad용 CURL도 `USE_APPLE_SECTRUST=ON`으로 별도 구성한다.

명시한 `TlsPolicy`의 CA·pin·호스트 이름·만료·용도·검증 깊이 계약은 유지한다. OS anchor 가져오기는 OpenSSL의 체인 검증을 대체하는 브라우저 신뢰/CT 정책 구현은 아니다. 사용자 정의 CA는 기존 명시적 정책으로 지정할 수 있다.

`iiNetwork.system_trust`는 실제 OS anchor가 적재되는지와 기본 클라이언트 컨텍스트 생성을 검사한다. 로컬 TLS 계약 검사는 별도의 테스트 CA·인증서로 성공·거부 경로를 검사한다. 외부 서비스 로그인 성공과 같은 결과로 집계하지 않는다.
