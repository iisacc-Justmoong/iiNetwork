# iPadOS 라이브러리 소비

iPhoneOS SDK·arm64 대상으로 iiSDKCore, iiJson, OpenSSL과 정적 CURL을 모두 같은 플랫폼으로 준비한다. 기존 최상위 호스트 `build/`를 보존할 때에는 상위 키트 드라이버에서 `add_subdirectory`로 소비하고 `build/ipados/build`에 중간 파일을 둔다.

Apple 플랫폼에서는 SDK의 `usr/include`를 CURL의 추가 헤더 경로에 넣지 않는다. C++ 표준 헤더보다 C 헤더가 먼저 선택되는 문제를 피하기 위한 계약이다. CURL의 Config 패키지가 `CURL::libcurl`을 별칭으로 제공하는 경우 실제 대상에 이 정규화를 적용하며, 키트의 자체 헤더 경로는 보존한다. `iiNetwork.AppleCurlIncludes`는 일반·별칭 두 대상의 구성을 검사한다.

기기 실행과 전송 기능별 검증은 별도이다. Congregation의 연결 iPad 실행은 네이티브 라이브러리 링크·서비스 초기화를 확인하며, 전체 네트워크 프로토콜이나 외부 서버 운영을 모두 검증한 것으로 간주하지 않는다.
