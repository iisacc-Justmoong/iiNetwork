#include <iiNetwork/Presentation.h>
#include <iiNetwork/Wire.h>
#include "ProtocolInternal.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <memory>

namespace ii::network
{
using detail::fail;
namespace
{
constexpr std::size_t maximum_cipher_bytes = 64 * 1024 * 1024, maximum_aad_bytes = 64 * 1024;
using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
auto cryptographic_failure() { return fail(Layer::presentation, ErrorCode::unavailable, "AES-256-GCM provider failed"); }
}
Aes256Gcm::Aes256Gcm(Key key) : key_(key) { OPENSSL_cleanse(key.data(), key.size()); }
Aes256Gcm::~Aes256Gcm() { OPENSSL_cleanse(key_.data(), key_.size()); }
Result<Aes256Gcm::Key> Aes256Gcm::generate_key()
{
    Key key;
    if (RAND_priv_bytes(key.data(), static_cast<int>(key.size())) != 1) return cryptographic_failure();
    return key;
}
Result<std::string> Aes256Gcm::seal(std::string_view plaintext, std::string_view aad) const
{
    if (plaintext.size() > maximum_cipher_bytes || aad.size() > maximum_aad_bytes)
        return fail(Layer::presentation, ErrorCode::too_large, "AEAD input limit exceeded");
    Context context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::string output(29 + plaintext.size() + 16, '\0'); output[0] = '\1';
    auto* bytes = reinterpret_cast<unsigned char*>(output.data());
    int written = 0, count = 0;
    if (!context || RAND_bytes(bytes + 1, 12) != 1 ||
        EVP_EncryptInit_ex2(context.get(), EVP_aes_256_gcm(), key_.data(), bytes + 1, nullptr) != 1 ||
        EVP_EncryptUpdate(context.get(), nullptr, &count, reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size())) != 1 ||
        EVP_EncryptUpdate(context.get(), bytes + 29, &written, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(context.get(), bytes + 29 + written, &count) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_GET_TAG, 16, bytes + 13) != 1)
        return cryptographic_failure();
    output.resize(29 + written + count); return output;
}
Result<std::string> Aes256Gcm::open(std::string_view ciphertext, std::string_view aad) const
{
    if (ciphertext.size() < 29 || ciphertext[0] != '\1')
        return fail(Layer::presentation, ErrorCode::malformed, "Invalid AEAD envelope");
    if (ciphertext.size() - 29 > maximum_cipher_bytes || aad.size() > maximum_aad_bytes)
        return fail(Layer::presentation, ErrorCode::too_large, "AEAD input limit exceeded");
    Context context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    const auto* bytes = reinterpret_cast<const unsigned char*>(ciphertext.data());
    std::string plaintext(ciphertext.size() - 29 + 16, '\0');
    auto* out = reinterpret_cast<unsigned char*>(plaintext.data());
    int written = 0, count = 0;
    if (!context || EVP_DecryptInit_ex2(context.get(), EVP_aes_256_gcm(), key_.data(), bytes + 1, nullptr) != 1 ||
        EVP_DecryptUpdate(context.get(), nullptr, &count, reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size())) != 1 ||
        EVP_DecryptUpdate(context.get(), out, &written, bytes + 29, static_cast<int>(ciphertext.size() - 29)) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG, 16, const_cast<unsigned char*>(bytes + 13)) != 1)
    { OPENSSL_cleanse(plaintext.data(), plaintext.size()); return cryptographic_failure(); }
    if (EVP_DecryptFinal_ex(context.get(), out + written, &count) != 1)
    {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return fail(Layer::presentation, ErrorCode::authentication_failed, "AEAD authentication failed");
    }
    plaintext.resize(written + count); return plaintext;
}
Result<std::string> PresentationLayer::encode(const core::Value& value, Encoding encoding) const
{
    if (encoding != Encoding::json && encoding != Encoding::base64_json)
        return fail(layer, ErrorCode::unsupported, "Unknown presentation encoding");
    auto result = ii::json::stringify(value, limits_);
    if (!result) return fail(layer, ErrorCode::malformed, result.error().message);
    if (encoding == Encoding::base64_json) *result = wire::base64(*result);
    if (result->size() > limits_.output_bytes) return fail(layer, ErrorCode::too_large, "Encoded presentation limit exceeded");
    return std::move(*result);
}
Result<core::Value> PresentationLayer::decode(std::string_view bytes, Encoding encoding) const
{
    if (bytes.size() > limits_.input_bytes) return fail(layer, ErrorCode::too_large, "Presentation input limit exceeded");
    std::string decoded;
    if (encoding == Encoding::base64_json)
    {
        auto result = wire::unbase64(bytes);
        if (!result) return fail(layer, ErrorCode::malformed, "Invalid presentation base64");
        decoded = std::move(*result); bytes = decoded;
    }
    else if (encoding != Encoding::json) return fail(layer, ErrorCode::unsupported, "Unknown presentation encoding");
    auto result = ii::json::parse(bytes, limits_);
    if (!result) return fail(layer, ErrorCode::malformed, result.error().message);
    return std::move(*result);
}
} // namespace ii::network
