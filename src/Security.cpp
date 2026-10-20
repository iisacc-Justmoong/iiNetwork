#include <iiNetwork/Security.h>
#include "CertificateInternal.h"
#include "ProtocolInternal.h"
#include "PathInternal.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>

namespace ii::network
{
namespace
{
auto invalid(std::string message) { return detail::fail(Layer::presentation, ErrorCode::invalid_argument, std::move(message)); }
std::string name(X509_NAME* value)
{
    auto memory = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new(BIO_s_mem()), BIO_free);
    if (!memory || X509_NAME_print_ex(memory.get(), value, 0, XN_FLAG_RFC2253) < 0) return {};
    char* bytes = nullptr; auto count = BIO_get_mem_data(memory.get(), &bytes);
    return count > 0 ? std::string(bytes, count) : std::string{};
}
Result<std::chrono::system_clock::time_point> time(const ASN1_TIME* value)
{
    std::tm utc{};
    if (ASN1_TIME_to_tm(value, &utc) != 1) return invalid("Malformed certificate time");
    using namespace std::chrono;
    year_month_day date{year(utc.tm_year + 1900), month(utc.tm_mon + 1), day(utc.tm_mday)};
    if (!date.ok()) return invalid("Invalid certificate calendar date");
    return system_clock::time_point(sys_days(date) + hours(utc.tm_hour) + minutes(utc.tm_min) + seconds(utc.tm_sec));
}
bool valid_path(std::string_view text) { return text.size() <= 32768 && text.find('\0') == text.npos; }
}
Result<void> validate(const TlsPolicy& policy)
{
    auto version = [](TlsVersion v) { return v == TlsVersion::tls1_2 || v == TlsVersion::tls1_3; };
    if (!version(policy.minimum) || !version(policy.maximum) || policy.minimum > policy.maximum ||
        !valid_path(policy.ca_file) || !valid_path(policy.ca_directory) ||
        !valid_path(policy.identity.certificate_chain_file) || !valid_path(policy.identity.private_key_file) ||
        !valid_path(policy.identity.private_key_password) ||
        policy.identity.certificate_chain_file.empty() != policy.identity.private_key_file.empty())
        return invalid("Invalid TLS version, trust path or certificate/key pair");
    return {};
}
bool CertificateInfo::valid_at(std::chrono::system_clock::time_point at) const { return at >= valid_from && at <= valid_until; }
Result<CertificateInfo> detail::certificate_info(X509* certificate)
{
    if (!certificate) return invalid("Missing certificate");
    CertificateInfo result; result.subject = name(X509_get_subject_name(certificate)); result.issuer = name(X509_get_issuer_name(certificate));
    auto from = time(X509_get0_notBefore(certificate)), until = time(X509_get0_notAfter(certificate));
    if (!from || !until) return invalid("Invalid certificate validity");
    result.valid_from = *from; result.valid_until = *until;
    BIGNUM* serial = ASN1_INTEGER_to_BN(X509_get_serialNumber(certificate), nullptr);
    if (!serial) return invalid("Invalid certificate serial");
    char* hex = BN_bn2hex(serial); BN_free(serial);
    if (!hex) return invalid("Certificate serial allocation failed");
    result.serial = hex; OPENSSL_free(hex);
    unsigned size = 0;
    if (X509_digest(certificate, EVP_sha256(), result.certificate_sha256.data(), &size) != 1 || size != 32)
        return invalid("Certificate digest failed");
    auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(X509_get_pubkey(certificate), EVP_PKEY_free);
    unsigned char* encoded = nullptr; int count = key ? i2d_PUBKEY(key.get(), &encoded) : -1;
    if (count <= 0) return invalid("Certificate public key encoding failed");
    bool digested = EVP_Digest(encoded, static_cast<std::size_t>(count), result.public_key_sha256.data(), &size, EVP_sha256(), nullptr) == 1;
    OPENSSL_free(encoded);
    if (!digested || size != 32) return invalid("Certificate public key digest failed");
    auto names = std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>(
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr)), GENERAL_NAMES_free);
    if (names)
        for (int i = 0; i < sk_GENERAL_NAME_num(names.get()) && i < 1024; ++i)
        {
            const auto* entry = sk_GENERAL_NAME_value(names.get(), i);
            if (entry->type == GEN_DNS)
            {
                auto* value = entry->d.dNSName;
                std::string text(reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)), ASN1_STRING_length(value));
                if (text.find('\0') == text.npos) result.dns_names.push_back(std::move(text));
            }
            else if (entry->type == GEN_IPADD)
            {
                auto* value = entry->d.iPAddress; auto n = ASN1_STRING_length(value); const auto* bytes = ASN1_STRING_get0_data(value);
                if (n == 4) result.ip_addresses.push_back(std::to_string(bytes[0]) + '.' + std::to_string(bytes[1]) + '.' + std::to_string(bytes[2]) + '.' + std::to_string(bytes[3]));
                else if (n == 16)
                {
                    constexpr char digits[] = "0123456789abcdef"; std::string text;
                    for (int b = 0; b < 16; ++b) { if (b && !(b % 2)) text += ':'; text += digits[bytes[b] >> 4]; text += digits[bytes[b] & 15]; }
                    result.ip_addresses.push_back(std::move(text));
                }
            }
        }
    return result;
}
Result<CertificateInfo> inspect_certificate(std::string_view pem)
{
    if (pem.empty() || pem.size() > 4 * 1024 * 1024) return invalid("Certificate PEM size limit exceeded");
    auto memory = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    auto certificate = std::unique_ptr<X509, decltype(&X509_free)>(memory ? PEM_read_bio_X509(memory.get(), nullptr, nullptr, nullptr) : nullptr, X509_free);
    if (!certificate) return invalid("Invalid certificate PEM");
    return detail::certificate_info(certificate.get());
}
Result<CertificateInfo> inspect_certificate_file(std::string_view path)
{
    if (!valid_path(path) || path.empty()) return invalid("Invalid certificate file path");
    std::ifstream stream(detail::utf8_path(path), std::ios::binary | std::ios::ate);
    auto count = stream.tellg();
    if (count <= 0 || count > 4 * 1024 * 1024) return invalid("Certificate file unavailable or oversized");
    std::string bytes(static_cast<std::size_t>(count), '\0'); stream.seekg(0); stream.read(bytes.data(), count);
    if (!stream) return invalid("Certificate file read failed");
    return inspect_certificate(bytes);
}
std::string public_key_pin(const std::array<unsigned char, 32>& bytes)
{
    std::array<unsigned char, 45> output{}; int count = EVP_EncodeBlock(output.data(), bytes.data(), bytes.size());
    return "sha256//" + std::string(reinterpret_cast<const char*>(output.data()), count);
}
} // namespace ii::network
