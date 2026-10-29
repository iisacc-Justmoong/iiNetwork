# 네트워크 소스 책임 분류

공개 헤더와 구현은 `src/` 아래에서 핵심 계약(`Core`), 전송(`Transport`), 보안(`Security`), 세션(`Session`), 표현(`Presentation`), 애플리케이션·오케스트레이션(`Application`)으로 나눈다. 내부 구현 헤더는 해당 책임과 함께 둔다.

생성된 빌드 forwarding 헤더와 설치 헤더는 기존 `<iiNetwork/...>` 경로를 유지한다. `tests/boundary.py`는 Qt 금지와 하위 계층의 의존 방향을, `tests/source_layout.cmake`는 구조를 검사한다. 로드 밸런서는 별도 소비자 예제로 유지한다.
