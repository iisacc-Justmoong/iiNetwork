cmake_minimum_required(VERSION 3.24)
project(iiNetwork VERSION 0.4.0 LANGUAGES CXX)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_BINARY_DIR STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}/build")
    message(FATAL_ERROR "iiNetwork uses its repository-local build/ directory")
endif()
include(CTest)
option(IINETWORK_BUILD_TESTS "Build iiNetwork contracts" ${PROJECT_IS_TOP_LEVEL})
option(IINETWORK_BUILD_EXAMPLES "Build iiNetwork example" ${PROJECT_IS_TOP_LEVEL})
find_package(iiSDKCore 0.18 CONFIG REQUIRED GLOBAL COMPONENTS Runtime
    HINTS "$ENV{HOME}/.local/SDK/iiSDKCore")
find_package(iiJson 0.1 CONFIG REQUIRED GLOBAL HINTS "$ENV{HOME}/.local/SDK/iiJson")
find_package(CURL 7.62 REQUIRED GLOBAL)
find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto SSL GLOBAL)
if(APPLE)
    # The SDK's C headers are already supplied by -isysroot. Adding usr/include
    # ahead of libc++ breaks <cmath>/<cstring> with Xcode 27.
    get_target_property(_curl_includes CURL::libcurl INTERFACE_INCLUDE_DIRECTORIES)
    list(REMOVE_ITEM _curl_includes "${CMAKE_OSX_SYSROOT}/usr/include")
    set_property(TARGET CURL::libcurl PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${_curl_includes}")
endif()
add_library(iiNetwork STATIC src/iiNetwork/Network.cpp src/iiNetwork/Wire.cpp src/iiNetwork/Layers.cpp src/iiNetwork/Session.cpp
    src/iiNetwork/Presentation.cpp src/iiNetwork/Application.cpp src/iiNetwork/Relay.cpp src/iiNetwork/Stack.cpp src/iiNetwork/Server.cpp
    src/iiNetwork/Address.cpp src/iiNetwork/ByteStream.cpp src/iiNetwork/Transport.cpp src/iiNetwork/Local.cpp src/iiNetwork/Security.cpp src/iiNetwork/Tls.cpp src/iiNetwork/Headers.cpp src/iiNetwork/Peer.cpp)
add_library(iiNetwork::iiNetwork ALIAS iiNetwork)
target_compile_features(iiNetwork PUBLIC cxx_std_23)
target_include_directories(iiNetwork PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(iiNetwork PUBLIC iiSDKCore::Runtime iiJson::iiJson PRIVATE CURL::libcurl OpenSSL::SSL OpenSSL::Crypto)
set_target_properties(iiNetwork PROPERTIES AUTOMOC OFF AUTORCC OFF AUTOUIC OFF
    CXX_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
if(WIN32)
    target_compile_definitions(iiNetwork PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_libraries(iiNetwork PRIVATE ws2_32 iphlpapi)
endif()
if(IINETWORK_BUILD_TESTS)
    find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
    add_executable(iiNetworkContracts tests/contracts.cpp)
    target_link_libraries(iiNetworkContracts PRIVATE iiNetwork::iiNetwork)
    set_target_properties(iiNetworkContracts PROPERTIES AUTOMOC OFF AUTORCC OFF AUTOUIC OFF)
    foreach(_case layers session presentation application native stack relay server)
        add_test(NAME iiNetwork.${_case} COMMAND iiNetworkContracts ${_case})
        set_tests_properties(iiNetwork.${_case} PROPERTIES TIMEOUT 30)
    endforeach()
    get_filename_component(_iinetwork_openssl_prefix "${OPENSSL_INCLUDE_DIR}" DIRECTORY)
    find_program(IINETWORK_OPENSSL_COMMAND NAMES openssl HINTS
        "${_iinetwork_openssl_prefix}/bin" "${_iinetwork_openssl_prefix}/tools/openssl" REQUIRED)
    add_executable(iiNetworkInterfaces tests/interfaces.cpp)
    target_link_libraries(iiNetworkInterfaces PRIVATE iiNetwork::iiNetwork)
    set_target_properties(iiNetworkInterfaces PROPERTIES AUTOMOC OFF AUTORCC OFF AUTOUIC OFF)
    add_test(NAME iiNetwork.TlsFixtures COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/create_tls_fixtures.py" "${IINETWORK_OPENSSL_COMMAND}"
        "${CMAKE_CURRENT_BINARY_DIR}/rich-fixtures")
    set_tests_properties(iiNetwork.TlsFixtures PROPERTIES FIXTURES_SETUP iiNetworkTls TIMEOUT 60)
    foreach(_case address tcp udp local tls http servers)
        add_test(NAME iiNetwork.interfaces.${_case} COMMAND iiNetworkInterfaces ${_case} "${CMAKE_CURRENT_BINARY_DIR}/rich-fixtures")
        set_tests_properties(iiNetwork.interfaces.${_case} PROPERTIES TIMEOUT 30 FIXTURES_REQUIRED iiNetworkTls)
    endforeach()
    add_executable(iiNetworkPeers tests/peers.cpp)
    target_link_libraries(iiNetworkPeers PRIVATE iiNetwork::iiNetwork)
    foreach(_case duplex lifecycle policy protocol transports)
        add_test(NAME iiNetwork.peers.${_case} COMMAND iiNetworkPeers ${_case} "${CMAKE_CURRENT_BINARY_DIR}/rich-fixtures")
        set_tests_properties(iiNetwork.peers.${_case} PROPERTIES TIMEOUT 30)
    endforeach()
    set_tests_properties(iiNetwork.peers.transports PROPERTIES FIXTURES_REQUIRED iiNetworkTls)
    set(_header_checks)
    foreach(_header Error Network Address ByteStream Transport Local Security Tls Headers Http Wire Layers Session Presentation Application Relay Server Stack Peer)
        set(_check "${CMAKE_CURRENT_BINARY_DIR}/header-checks/${_header}.cpp")
        configure_file(cmake/header.cpp.in "${_check}" @ONLY)
        list(APPEND _header_checks "${_check}")
    endforeach()
    add_library(iiNetworkPublicHeaders OBJECT ${_header_checks})
    target_link_libraries(iiNetworkPublicHeaders PRIVATE iiNetwork::iiNetwork)
    add_test(NAME iiNetwork.Boundary COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/boundary.py" "${CMAKE_CURRENT_SOURCE_DIR}")
endif()
if(IINETWORK_BUILD_EXAMPLES)
    add_executable(iiNetworkExample examples/roundtrip.cpp)
    target_link_libraries(iiNetworkExample PRIVATE iiNetwork::iiNetwork)
    set_target_properties(iiNetworkExample PROPERTIES AUTOMOC OFF AUTORCC OFF AUTOUIC OFF)
    add_executable(iiNetworkPeerExample examples/peers.cpp)
    target_link_libraries(iiNetworkPeerExample PRIVATE iiNetwork::iiNetwork)
    set_target_properties(iiNetworkPeerExample PROPERTIES AUTOMOC OFF AUTORCC OFF AUTOUIC OFF)
    if(IINETWORK_BUILD_TESTS)
        add_test(NAME iiNetwork.Example COMMAND iiNetworkExample)
        add_test(NAME iiNetwork.PeerExample COMMAND iiNetworkPeerExample)
        set_tests_properties(iiNetwork.PeerExample PROPERTIES TIMEOUT 10)
    endif()
endif()
install(TARGETS iiNetwork EXPORT iiNetworkTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES
    src/iiNetwork/Address.h
    src/iiNetwork/Application.h
    src/iiNetwork/ByteStream.h
    src/iiNetwork/Error.h
    src/iiNetwork/Headers.h
    src/iiNetwork/Http.h
    src/iiNetwork/Layers.h
    src/iiNetwork/Local.h
    src/iiNetwork/Network.h
    src/iiNetwork/Peer.h
    src/iiNetwork/Presentation.h
    src/iiNetwork/Relay.h
    src/iiNetwork/Security.h
    src/iiNetwork/Server.h
    src/iiNetwork/Session.h
    src/iiNetwork/Stack.h
    src/iiNetwork/Tls.h
    src/iiNetwork/Transport.h
    src/iiNetwork/Wire.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iiNetwork)
install(EXPORT iiNetworkTargets NAMESPACE iiNetwork:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iiNetwork)
configure_package_config_file(cmake/iiNetworkConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/iiNetworkConfig.cmake" INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iiNetwork)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/iiNetworkConfigVersion.cmake"
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/iiNetworkConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/iiNetworkConfigVersion.cmake" DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iiNetwork)
install(FILES README.md LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/iiNetwork)
install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DATADIR}/iiNetwork/docs)
