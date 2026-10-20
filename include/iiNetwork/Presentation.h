#pragma once
#include <iiNetwork/Error.h>
#include <iiJson/Json.h>
#include <array>
#include <string_view>

namespace ii::network
{
enum class Encoding : unsigned char { json = 1, base64_json = 2 };
class PayloadCipher
{
  public:
    virtual ~PayloadCipher() = default;
    virtual Result<std::string> seal(std::string_view plaintext, std::string_view associated_data) const = 0;
    virtual Result<std::string> open(std::string_view ciphertext, std::string_view associated_data) const = 0;
};
class Aes256Gcm final : public PayloadCipher
{
  public:
    using Key = std::array<unsigned char, 32>;
    explicit Aes256Gcm(Key);
    ~Aes256Gcm() override;
    Aes256Gcm(const Aes256Gcm&) = delete;
    Aes256Gcm& operator=(const Aes256Gcm&) = delete;
    static Result<Key> generate_key();
    // v1 | random 96-bit nonce | 128-bit tag | ciphertext; AAD is not serialized.
    Result<std::string> seal(std::string_view, std::string_view associated_data = {}) const override;
    Result<std::string> open(std::string_view, std::string_view associated_data = {}) const override;
  private:
    Key key_;
};
class PresentationLayer final
{
  public:
    static constexpr Layer layer = Layer::presentation;
    explicit PresentationLayer(ii::json::Limits limits = {}) : limits_(limits) {}
    Result<std::string> encode(const core::Value&, Encoding = Encoding::json) const;
    Result<core::Value> decode(std::string_view, Encoding = Encoding::json) const;
  private:
    ii::json::Limits limits_;
};
} // namespace ii::network
