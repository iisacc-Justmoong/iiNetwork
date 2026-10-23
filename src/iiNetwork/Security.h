#pragma once
#include <iiNetwork/Error.h>
#include <array>
#include <chrono>
#include <optional>
#include <string_view>
#include <vector>

namespace ii::network
{
enum class TlsVersion { tls1_2, tls1_3 };
struct TlsIdentity final
{
    std::string certificate_chain_file, private_key_file, private_key_password;
    // An ephemeral identity can stay in memory; do not combine PEM and files.
    std::string certificate_chain_pem, private_key_pem;
};
struct TlsPolicy final
{
    TlsVersion minimum = TlsVersion::tls1_2, maximum = TlsVersion::tls1_3;
    std::string ca_file, ca_directory;
    TlsIdentity identity;
    std::optional<std::array<unsigned char, 32>> public_key_sha256;
    // Out-of-band trust of this exact leaf certificate (for QR/LAN pairing).
    // Validity, TLS security and certificate purpose are still enforced.
    std::optional<std::array<unsigned char, 32>> trusted_certificate_sha256;
};
struct CertificateInfo final
{
    std::string subject, issuer, serial;
    std::chrono::system_clock::time_point valid_from, valid_until;
    std::array<unsigned char, 32> certificate_sha256{}, public_key_sha256{};
    std::vector<std::string> dns_names, ip_addresses;
    [[nodiscard]] bool valid_at(std::chrono::system_clock::time_point = std::chrono::system_clock::now()) const;
};
Result<CertificateInfo> inspect_certificate(std::string_view pem);
Result<CertificateInfo> inspect_certificate_file(std::string_view path);
Result<void> validate(const TlsPolicy&);
std::string public_key_pin(const std::array<unsigned char, 32>&); // sha256//base64(SPKI digest)
} // namespace ii::network
