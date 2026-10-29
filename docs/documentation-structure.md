# iiNetwork 문서 구조

<!-- workspace-docs:blueprint -->

<!-- workspace-docs:blueprint:start -->
이 프로젝트는 사람과 에이전트가 같은 계약을 서로 다른 형식으로 읽도록 문서를 구성한다.

- 루트 `README.md`: 사람용 영문 개요이다.
- 루트 `AGENT.md`: 프로젝트별 에이전트 지침과 문서 탐색 진입점이다.
- `docs/README.md`: 인간용 문서 색인이다.
- `agent-index.json`: 문서 ID, 원문 경로, JSON 투영 경로와 원문 해시의 색인이다.
- 일반 문서 `name.md`와 `name.agent.json`은 같은 내용을 서로 다른 형식으로 제공한다.
- 루트 진입 문서의 JSON은 `entrypoints/`에, 문서 디렉터리 밖의 문서·지침·증거의 JSON은 `mirrors/`에 둔다.
- `agent-document.schema.json`은 iiJson의 이식 가능한 Schema 정의로 된 형식 묶음이다.

JSON은 절, 줄 범위, 원문 블록, 명령·링크·표·규칙 후보를 구조화한다. 원문 블록을 결합하면 Markdown 바이트를 복원할 수 있어야 한다. JSON의 SHA-256과 현재 Markdown이 일치해야 한다.

규칙 후보와 언어 판정은 원문 기반 검색 보조 정보이다. 과거 검증 기록·예제·미완료 설명을 현재의 실행 지시 또는 완료 증거로 승격하지 않는다. 코드 블록은 변환 중 실행하지 않는다.

원본 Markdown을 수정한 뒤 agent JSON과 색인을 함께 재생성하고 검증한다. 외부 원본과 라이선스는 보존한다. 기존 경로가 필요한 이동 문서는 안내 파일로 연결하며 실제 내용은 하위 문서에 둔다.
<!-- workspace-docs:blueprint:end -->
