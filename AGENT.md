# iiNetwork 작업 지침

이 모듈은 앱과 게임이 함께 사용하는 iiSDK 네트워크 기반이다. C++23과 표준 라이브러리, 기존 iiSDK 및 허용된 오픈소스를 사용한다. Qt 타입·패키지 의존성과 상위 제품·iiWebServer 의존성을 추가하지 않는다.

- SDK 소스와 공개 헤더는 `src/iiNetwork/`에 같은 이름으로 함께 둔다. 설치할 때만 소비자용 `include/iiNetwork/`에 배치한다.
- 새 예제는 `example/`, 검사는 `tests/`, 한국어 사용·유지보수 문서는 `docs/`에 둔다. 기존 `examples/`의 경로는 이전 소비자 호환성을 위해 보존한다. README는 영어로 유지한다.
- 실행 중 작업과 기존 변경을 보존한다. 빌드 산출물·검증 설치본·테스트 자원은 저장소의 `build/` 아래에 둔다. 독립 최상위 구성은 저장소의 `build/`를 사용하고, 임베디드 검증은 그 하위의 `build/` 디렉터리를 사용한다.
- 구현 전에 의미 있는 실패 검사를 마련한다. 모든 소스 변경에는 문서와 실제 빌드·테스트를 동반한다. 실제 소켓, 설치 소비자, 수명·경계 조건을 검증하고 실행한 플랫폼 범위를 구분한다.
- 하위 전송·세션·표현 계층에서 애플리케이션·오케스트레이션 계층을 참조하지 않는다. `tests/boundary.py`가 이 방향과 Qt 제거를 검사한다.
- 네트워크 객체와 콜백은 소유 iiSDKCore 이벤트 루프 스레드에 한정한다. 콜백 중 삭제·종료·재접속, 큐·입력 한도와 타임아웃을 처리한다. 미래 기능을 위한 추측성 계층보다 실제 수정 이유에 따라 구현을 분리한다.
- 로드 밸런서의 Core 조합은 기본 타깃이 아니라 독립적으로 구성하는 `example/LoadBalancer`가 소유한다. 기본 모듈에 다시 통합하지 않는다. 다른 Core·iiJson 의존성은 아직 이전 전이다.
- 실시간 입장권의 키는 TLS 또는 신뢰한 IPC로만 전달하고 URL·로그·테스트 결과 파일에 출력하지 않는다. `tests/realtime_process.py`는 비공개 익명 파이프에서만 임시 입장권을 전달한다.
- `install.sh`는 빌드·소스 검사·설치·설치 소비자 검증을 순서대로 수행한다. 기존 전역 설치 교체를 원하지 않는 검증에서는 `INSTALL_PREFIX="$PWD/build/package"`를 지정한다.

실시간 데이터 계약은 `docs/Realtime.md`, 기존 피어 제어 계약은 `docs/Peers.md`, 일반 통신 API는 `docs/Interfaces.md`를 먼저 읽는다. 기능 추가는 그 경계와 기존 공개 API를 보존하면서 수행한다.

<!-- workspace-docs:agent:start -->
## 문서 구조와 에이전트 탐색

- 프로젝트 루트의 `README.md`는 사람용 영문 진입 문서이며 `AGENT.md`는 에이전트 진입점이다.
- 하위 인간용 Markdown과 구조화된 agent JSON을 함께 유지한다. Markdown이 원본이며 JSON은 원문 해시와 줄 범위를 가진 파생 문서이다.
- 먼저 [docs/agent-index.json](docs/agent-index.json)에서 관련 문서와 JSON 투영을 찾는다. 원문 SHA-256이 다르면 현재 Markdown을 읽고 투영을 갱신한다.
- JSON의 규칙 후보는 검색용 어휘 일치 결과이다. 과거 기록·예제·실패 상태를 현재 지시나 검증 완료로 자동 해석하지 않는다.
- 기존 프로젝트별 규칙, 동결된 증거, 라이선스, 외부 원본, 사용자 데이터와 다른 작업의 변경을 보존한다.
- 이 문서 재편 지침은 과거 작업의 기능 구현·배포를 자동 재개하라는 요청이 아니다. 현재 사용자의 작업 범위를 우선한다.
- 문서를 수정하면 JSON 쌍·색인을 함께 갱신하고 검증한다. 기존 소스 변경에 대한 빌드·테스트 규칙은 계속 따른다.

Workspace에서 이 프로젝트의 문서를 갱신하는 명령은 다음과 같다.

```sh
python3 ../../Engineering/WorkspaceDocumentation/App/workspace_docs.py --workspace ../.. sync --project SDK/iiNetwork
```
<!-- workspace-docs:agent:end -->
