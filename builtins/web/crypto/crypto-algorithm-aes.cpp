// AES-CTR, AES-CBC and AES-GCM (import, generate, export, encrypt, decrypt),
// AES-KW import, HMAC key generation, and the export of secret keys.
// https://w3c.github.io/webcrypto/#aes-ctr
// https://w3c.github.io/webcrypto/#aes-cbc
// https://w3c.github.io/webcrypto/#aes-gcm
// https://w3c.github.io/webcrypto/#aes-kw
#include <cmath>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "../base64.h"
#include "../dom-exception.h"

#include "crypto-algorithm.h"
#include "encode.h"
#include "host_api.h"
#include "js/Array.h"
#include "js/ArrayBuffer.h"

namespace builtins::web::crypto {

using dom_exception::DOMException;

namespace {

struct EvpCipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX *ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

constexpr size_t AES_BLOCK = 16;

JSObject *to_array_buffer(JSContext *cx, std::span<const uint8_t> bytes) {
  if (bytes.empty()) {
    return JS::NewArrayBuffer(cx, 0);
  }
  mozilla::UniquePtr<uint8_t[], JS::FreePolicy> buf{
      static_cast<uint8_t *>(JS_malloc(cx, bytes.size()))};
  if (!buf) {
    JS_ReportOutOfMemory(cx);
    return nullptr;
  }
  std::copy(bytes.begin(), bytes.end(), buf.get());
  JSObject *array_buffer = JS::NewArrayBufferWithContents(
      cx, bytes.size(), buf.get(), JS::NewArrayBufferOutOfMemory::CallerMustFreeMemory);
  if (!array_buffer) {
    return nullptr;
  }
  // `array_buffer` now owns the bytes.
  static_cast<void>(buf.release());
  return array_buffer;
}

// A dictionary member of type BufferSource. Absent is nullopt; a member of the
// wrong type throws a TypeError.
bool buffer_member(JSContext *cx, JS::HandleObject params, const char *dictionary,
                   const char *member, bool required,
                   std::optional<std::vector<uint8_t>> *out) {
  JS::RootedValue val(cx);
  if (!JS_GetProperty(cx, params, member, &val)) {
    return false;
  }
  std::string desc = std::string(dictionary) + "." + member;
  if (val.isUndefined()) {
    if (required) {
      return api::throw_error(cx, api::Errors::TypeError, "crypto.subtle", desc.c_str(),
                              "be present");
    }
    *out = std::nullopt;
    return true;
  }
  auto buffer = value_to_buffer(cx, val, desc.c_str());
  if (!buffer.has_value()) {
    return false;
  }
  *out = std::vector<uint8_t>(buffer->begin(), buffer->end());
  return true;
}

// A dictionary member of an integer type with [EnforceRange]
// (https://webidl.spec.whatwg.org/#abstract-opdef-converttoint).
bool integer_member(JSContext *cx, JS::HandleObject params, const char *dictionary,
                    const char *member, bool required, double max, std::optional<double> *out) {
  JS::RootedValue val(cx);
  if (!JS_GetProperty(cx, params, member, &val)) {
    return false;
  }
  std::string desc = std::string(dictionary) + "." + member;
  if (val.isUndefined()) {
    if (required) {
      return api::throw_error(cx, api::Errors::TypeError, "crypto.subtle", desc.c_str(),
                              "be present");
    }
    *out = std::nullopt;
    return true;
  }
  double number = 0;
  if (!JS::ToNumber(cx, val, &number)) {
    return false;
  }
  if (!std::isfinite(number)) {
    return api::throw_error(cx, api::Errors::TypeError, "crypto.subtle", desc.c_str(),
                            "be a finite number");
  }
  number = std::trunc(number);
  if (number < 0 || number > max) {
    return api::throw_error(cx, api::Errors::TypeError, "crypto.subtle", desc.c_str(),
                            "be in range");
  }
  *out = number;
  return true;
}

// The algorithm's parameters: the dictionary itself, or a new one holding only
// the name when the algorithm was given as a string.
JSObject *parameters_object(JSContext *cx, JS::HandleValue value) {
  if (value.isObject()) {
    return &value.toObject();
  }
  JS::RootedObject params(cx, JS_NewPlainObject(cx));
  if (!params || !JS_SetProperty(cx, params, "name", value)) {
    return nullptr;
  }
  return params;
}

const char *aes_jwk_suffix(CryptoAlgorithmIdentifier identifier) {
  switch (identifier) {
  case CryptoAlgorithmIdentifier::AES_CTR:
    return "CTR";
  case CryptoAlgorithmIdentifier::AES_CBC:
    return "CBC";
  case CryptoAlgorithmIdentifier::AES_GCM:
    return "GCM";
  case CryptoAlgorithmIdentifier::AES_KW:
    return "KW";
  default:
    MOZ_ASSERT_UNREACHABLE("not an AES algorithm");
    return "";
  }
}

// AES-KW keys may only wrap and unwrap; the other three may also encrypt and
// decrypt.
bool aes_usages_valid(CryptoAlgorithmIdentifier identifier, CryptoKeyUsages usages) {
  uint8_t allowed = CryptoKeyUsages::wrap_key_flag | CryptoKeyUsages::unwrap_key_flag;
  if (identifier != CryptoAlgorithmIdentifier::AES_KW) {
    allowed |= CryptoKeyUsages::encrypt_flag | CryptoKeyUsages::decrypt_flag;
  }
  return (usages.toInt() & ~allowed) == 0;
}

bool usages_contain(CryptoKeyUsages outer, CryptoKeyUsages inner) {
  return (outer.toInt() & inner.toInt()) == inner.toInt();
}

// https://w3c.github.io/webcrypto/#dfn-AesKeyAlgorithm
JSObject *aes_key_algorithm(JSContext *cx, CryptoAlgorithmIdentifier identifier, size_t length) {
  JS::RootedObject algorithm(cx, JS_NewPlainObject(cx));
  if (!algorithm) {
    return nullptr;
  }
  JS::RootedString name(cx, JS_NewStringCopyZ(cx, algorithmName(identifier)));
  if (!name) {
    return nullptr;
  }
  JS::RootedValue name_val(cx, JS::StringValue(name));
  JS::RootedValue length_val(cx, JS::NumberValue(static_cast<double>(length)));
  if (!JS_SetProperty(cx, algorithm, "name", name_val) ||
      !JS_SetProperty(cx, algorithm, "length", length_val)) {
    return nullptr;
  }
  return algorithm;
}

const EVP_CIPHER *aes_cipher(CryptoAlgorithmIdentifier identifier, size_t key_bytes) {
  switch (identifier) {
  case CryptoAlgorithmIdentifier::AES_GCM:
    return key_bytes == 16   ? EVP_aes_128_gcm()
           : key_bytes == 24 ? EVP_aes_192_gcm()
           : key_bytes == 32 ? EVP_aes_256_gcm()
                             : nullptr;
  case CryptoAlgorithmIdentifier::AES_CBC:
    return key_bytes == 16   ? EVP_aes_128_cbc()
           : key_bytes == 24 ? EVP_aes_192_cbc()
           : key_bytes == 32 ? EVP_aes_256_cbc()
                             : nullptr;
  case CryptoAlgorithmIdentifier::AES_CTR:
    return key_bytes == 16   ? EVP_aes_128_ctr()
           : key_bytes == 24 ? EVP_aes_192_ctr()
           : key_bytes == 32 ? EVP_aes_256_ctr()
                             : nullptr;
  default:
    return nullptr;
  }
}

JSObject *operation_error(JSContext *cx, const char *message) {
  DOMException::raise(cx, message, "OperationError");
  return nullptr;
}

bool valid_gcm_tag_length(uint8_t bits) {
  switch (bits) {
  case 32:
  case 64:
  case 96:
  case 104:
  case 112:
  case 120:
  case 128:
    return true;
  default:
    return false;
  }
}

// One pass of a stream cipher (CTR) or a padded block cipher (CBC) over `in`,
// appended to `out`.
bool cipher_pass(const EVP_CIPHER *cipher, bool encrypt, std::span<const uint8_t> key,
                 std::span<const uint8_t> iv, std::span<const uint8_t> in,
                 std::vector<uint8_t> *out) {
  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return false;
  }
  if (1 != EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data(), encrypt ? 1 : 0)) {
    return false;
  }
  size_t start = out->size();
  out->resize(start + in.size() + AES_BLOCK);
  int written = 0;
  if (!in.empty() && 1 != EVP_CipherUpdate(ctx.get(), out->data() + start, &written, in.data(),
                                           static_cast<int>(in.size()))) {
    return false;
  }
  int final_written = 0;
  if (1 != EVP_CipherFinal_ex(ctx.get(), out->data() + start + written, &final_written)) {
    return false;
  }
  out->resize(start + written + final_written);
  return true;
}

} // namespace

// https://w3c.github.io/webcrypto/#aes-gcm-operations, "import key" (the
// AES-CTR, AES-CBC and AES-KW steps are the same but for the names).
JSObject *CryptoAlgorithmAES_Import::importKey(JSContext *cx, CryptoKeyFormat format,
                                               JS::HandleValue key_data, bool extractable,
                                               CryptoKeyUsages usages) {
  std::unique_ptr<JsonWebKey> jwk;
  KeyData data;
  switch (format) {
  case CryptoKeyFormat::Raw: {
    auto buffer = value_to_buffer(cx, key_data, "crypto.subtle.importKey: keyData");
    if (!buffer.has_value()) {
      return nullptr;
    }
    data = buffer.value();
    break;
  }
  case CryptoKeyFormat::Jwk: {
    // Rejects anything but kty "oct".
    jwk = JsonWebKey::parse(cx, key_data, "oct");
    if (!jwk) {
      return nullptr;
    }
    data = jwk.get();
    break;
  }
  default: {
    // 1. If usages contains an entry which is not "encrypt", "decrypt",
    // "wrapKey" or "unwrapKey", then throw a SyntaxError.
    if (!aes_usages_valid(identifier_, usages)) {
      DOMException::raise(cx, "Unsupported key usage for an AES key", "SyntaxError");
      return nullptr;
    }
    // Otherwise: throw a NotSupportedError.
    DOMException::raise(cx, "Supplied format is not supported", "NotSupportedError");
    return nullptr;
  }
  }
  return importKey(cx, format, data, extractable, usages);
}

JSObject *CryptoAlgorithmAES_Import::importKey(JSContext *cx, CryptoKeyFormat format,
                                               KeyData key_data, bool extractable,
                                               CryptoKeyUsages usages) {
  // 1. If usages contains an entry which is not "encrypt", "decrypt", "wrapKey"
  // or "unwrapKey", then throw a SyntaxError.
  if (!aes_usages_valid(identifier_, usages)) {
    DOMException::raise(cx, "Unsupported key usage for an AES key", "SyntaxError");
    return nullptr;
  }

  std::vector<uint8_t> data;
  // 2. If format is "raw":
  if (format == CryptoKeyFormat::Raw) {
    // 2.1 Let data be keyData.
    auto raw = std::get<std::span<uint8_t>>(key_data);
    data.assign(raw.begin(), raw.end());
    // 2.2 If the length in bits of data is not 128, 192 or 256 then throw a
    // DataError.
    if (data.size() != 16 && data.size() != 24 && data.size() != 32) {
      DOMException::raise(cx, "AES key data must be 128, 192 or 256 bits", "DataError");
      return nullptr;
    }
  } else if (format == CryptoKeyFormat::Jwk) {
    auto *jwk = std::get<JsonWebKey *>(key_data);
    MOZ_ASSERT(jwk);
    // 2.3 If the kty field of jwk is not "oct", then throw a DataError
    // (done by JsonWebKey::parse).
    // 2.4 If jwk does not meet the requirements of Section 6.4 of JSON Web
    // Algorithms [JWA], then throw a DataError.
    if (!jwk->k.has_value()) {
      DOMException::raise(cx, "The JWK member 'k' is missing", "DataError");
      return nullptr;
    }
    // 2.5 Let data be the octet string obtained by decoding the k field of jwk.
    auto decoded = base64::forgivingBase64Decode(jwk->k.value(), base64::base64URLDecodeTable);
    if (decoded.isErr()) {
      DOMException::raise(cx, "The JWK member 'k' could not be base64url decoded", "DataError");
      return nullptr;
    }
    auto bytes = decoded.unwrap();
    data.assign(bytes.begin(), bytes.end());
    // 2.6 If data has length 128, 192 or 256 bits: if the alg field of jwk is
    // present, and is not "A128<mode>", "A192<mode>" or "A256<mode>"
    // respectively, then throw a DataError. Otherwise: throw a DataError.
    if (data.size() != 16 && data.size() != 24 && data.size() != 32) {
      DOMException::raise(cx, "AES key data must be 128, 192 or 256 bits", "DataError");
      return nullptr;
    }
    std::string expected_alg =
        "A" + std::to_string(data.size() * 8) + aes_jwk_suffix(identifier_);
    if (jwk->alg.has_value() && jwk->alg.value() != expected_alg) {
      DOMException::raise(cx, "The JWK 'alg' member does not match the key", "DataError");
      return nullptr;
    }
    // 2.7 If usages is non-empty and the use field of jwk is present and is not
    // "enc", then throw a DataError.
    if (!usages.isEmpty() && jwk->use.has_value() && jwk->use.value() != "enc") {
      DOMException::raise(cx, "The JWK 'use' member must be 'enc'", "DataError");
      return nullptr;
    }
    // 2.8 If the key_ops field of jwk is present, and is invalid according to
    // the requirements of JSON Web Key [JWK] or does not contain all of the
    // specified usages values, then throw a DataError.
    if (!jwk->key_ops.empty() &&
        !usages_contain(CryptoKeyUsages::from(jwk->key_ops), usages)) {
      DOMException::raise(cx, "The JWK 'key_ops' member must contain every requested usage",
                          "DataError");
      return nullptr;
    }
    // 2.9 If the ext field of jwk is present and has the value false and
    // extractable is true, then throw a DataError.
    if (jwk->ext.has_value() && !jwk->ext.value() && extractable) {
      DOMException::raise(cx, "The JWK is not extractable", "DataError");
      return nullptr;
    }
  } else {
    // Otherwise: throw a NotSupportedError.
    DOMException::raise(cx, "Supplied format is not supported", "NotSupportedError");
    return nullptr;
  }

  // SubtleCrypto.importKey step 9: a secret key with no usages is a
  // SyntaxError.
  if (usages.isEmpty()) {
    DOMException::raise(cx, "An AES key needs at least one usage", "SyntaxError");
    return nullptr;
  }

  // 3. Let key be a new CryptoKey object representing an AES key with value
  // data.
  // 4. Set the [[type]] internal slot of key to "secret".
  // 5. Let algorithm be a new AesKeyAlgorithm.
  // 6. Set the name attribute of algorithm to the algorithm's name.
  // 7. Set the length attribute of algorithm to the length, in bits, of data.
  // 8. Set the [[algorithm]] internal slot of key to algorithm.
  this->length = data.size() * 8;
  JS::RootedObject algorithm(cx, aes_key_algorithm(cx, identifier_, this->length));
  if (!algorithm) {
    return nullptr;
  }
  // 9. Return key.
  return CryptoKey::createSecret(cx, algorithm, data, extractable, usages);
}

std::unique_ptr<CryptoAlgorithmEncryptDecrypt>
CryptoAlgorithmEncryptDecrypt::normalize(JSContext *cx, JS::HandleValue value) {
  auto identifierResult = normalizeIdentifier(cx, value);
  if (identifierResult.isErr()) {
    return nullptr;
  }
  auto identifier = identifierResult.unwrap();
  JS::RootedObject params(cx, parameters_object(cx, value));
  if (!params) {
    return nullptr;
  }

  // https://w3c.github.io/webcrypto/#h-note-15: RSA-OAEP, AES-CTR, AES-CBC and
  // AES-GCM support encrypt and decrypt.
  switch (identifier) {
  case CryptoAlgorithmIdentifier::AES_GCM:
    return CryptoAlgorithmAES_GCM::fromParameters(cx, params);
  case CryptoAlgorithmIdentifier::AES_CBC:
    return CryptoAlgorithmAES_CBC::fromParameters(cx, params);
  case CryptoAlgorithmIdentifier::AES_CTR:
    return CryptoAlgorithmAES_CTR::fromParameters(cx, params);
  case CryptoAlgorithmIdentifier::RSA_OAEP:
    DOMException::raise(cx, "Supplied algorithm is not yet supported", "NotSupportedError");
    return nullptr;
  default:
    DOMException::raise(cx, "Supplied algorithm does not support the encrypt operation",
                        "NotSupportedError");
    return nullptr;
  }
}

std::unique_ptr<CryptoAlgorithmAES_GCM>
CryptoAlgorithmAES_GCM::fromParameters(JSContext *cx, JS::HandleObject parameters) {
  auto result = std::make_unique<CryptoAlgorithmAES_GCM>();
  std::optional<std::vector<uint8_t>> iv;
  if (!buffer_member(cx, parameters, "AesGcmParams", "iv", true, &iv)) {
    return nullptr;
  }
  result->iv = std::move(iv.value());
  if (!buffer_member(cx, parameters, "AesGcmParams", "additionalData", false,
                     &result->additionalData)) {
    return nullptr;
  }
  std::optional<double> tag_length;
  if (!integer_member(cx, parameters, "AesGcmParams", "tagLength", false, 255, &tag_length)) {
    return nullptr;
  }
  if (tag_length.has_value()) {
    result->tagLength = static_cast<uint8_t>(tag_length.value());
  }
  return result;
}

// https://w3c.github.io/webcrypto/#aes-gcm-operations, "encrypt"
JSObject *CryptoAlgorithmAES_GCM::encrypt(JSContext *cx, JS::HandleObject key,
                                          std::span<uint8_t> data) {
  // 1-3. The plaintext, iv and additionalData lengths cannot exceed what a
  // BufferSource can hold here.
  // 4. If the tagLength member of normalizedAlgorithm is present: if it is not
  // one of 32, 64, 96, 104, 112, 120 or 128, then throw an OperationError.
  if (!valid_gcm_tag_length(tagLength)) {
    return operation_error(cx, "AES-GCM tagLength must be 32, 64, 96, 104, 112, 120 or 128");
  }
  if (iv.empty()) {
    return operation_error(cx, "AES-GCM iv must not be empty");
  }
  auto key_data = CryptoKey::secretKeyData(key);
  const EVP_CIPHER *cipher = aes_cipher(CryptoAlgorithmIdentifier::AES_GCM, key_data.size());
  if (!cipher) {
    return operation_error(cx, "Invalid AES key length");
  }
  size_t tag_bytes = tagLength / 8;

  // 5-8. Encrypt with the key, iv and additionalData, and append the first
  // tagLength bits of the authentication tag to the ciphertext.
  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx || 1 != EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) ||
      1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()),
                               nullptr) ||
      1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key_data.data(), iv.data())) {
    return operation_error(cx, "AES-GCM encryption failed");
  }
  int written = 0;
  if (additionalData.has_value() && !additionalData->empty() &&
      1 != EVP_EncryptUpdate(ctx.get(), nullptr, &written, additionalData->data(),
                             static_cast<int>(additionalData->size()))) {
    return operation_error(cx, "AES-GCM encryption failed");
  }
  std::vector<uint8_t> out(data.size() + tag_bytes);
  written = 0;
  if (!data.empty() && 1 != EVP_EncryptUpdate(ctx.get(), out.data(), &written, data.data(),
                                              static_cast<int>(data.size()))) {
    return operation_error(cx, "AES-GCM encryption failed");
  }
  int final_written = 0;
  if (1 != EVP_EncryptFinal_ex(ctx.get(), out.data() + written, &final_written)) {
    return operation_error(cx, "AES-GCM encryption failed");
  }
  size_t ciphertext_len = written + final_written;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_bytes),
                               out.data() + ciphertext_len)) {
    return operation_error(cx, "AES-GCM encryption failed");
  }
  out.resize(ciphertext_len + tag_bytes);
  // 9. Return a new ArrayBuffer containing ciphertext.
  return to_array_buffer(cx, out);
}

// https://w3c.github.io/webcrypto/#aes-gcm-operations, "decrypt"
JSObject *CryptoAlgorithmAES_GCM::decrypt(JSContext *cx, JS::HandleObject key,
                                          std::span<uint8_t> data) {
  // 1. If the tagLength member of normalizedAlgorithm is present: if it is not
  // one of 32, 64, 96, 104, 112, 120 or 128, then throw an OperationError.
  if (!valid_gcm_tag_length(tagLength)) {
    return operation_error(cx, "AES-GCM tagLength must be 32, 64, 96, 104, 112, 120 or 128");
  }
  size_t tag_bytes = tagLength / 8;
  // 2. If ciphertext has a length less than tagLength bits, then throw an
  // OperationError.
  if (data.size() < tag_bytes) {
    return operation_error(cx, "AES-GCM ciphertext is shorter than its tag");
  }
  if (iv.empty()) {
    return operation_error(cx, "AES-GCM iv must not be empty");
  }
  auto key_data = CryptoKey::secretKeyData(key);
  const EVP_CIPHER *cipher = aes_cipher(CryptoAlgorithmIdentifier::AES_GCM, key_data.size());
  if (!cipher) {
    return operation_error(cx, "Invalid AES key length");
  }
  // 5. Let tag be the last tagLength bits of ciphertext.
  // 6. Let actualCiphertext be the result of removing the last tagLength bits
  // from ciphertext.
  auto ciphertext = data.first(data.size() - tag_bytes);
  std::vector<uint8_t> tag(data.end() - tag_bytes, data.end());

  // 7-8. Decrypt and verify; a failed verification is an OperationError.
  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx || 1 != EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) ||
      1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()),
                               nullptr) ||
      1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key_data.data(), iv.data())) {
    return operation_error(cx, "AES-GCM decryption failed");
  }
  int written = 0;
  if (additionalData.has_value() && !additionalData->empty() &&
      1 != EVP_DecryptUpdate(ctx.get(), nullptr, &written, additionalData->data(),
                             static_cast<int>(additionalData->size()))) {
    return operation_error(cx, "AES-GCM decryption failed");
  }
  std::vector<uint8_t> out(ciphertext.size() + AES_BLOCK);
  written = 0;
  if (!ciphertext.empty() &&
      1 != EVP_DecryptUpdate(ctx.get(), out.data(), &written, ciphertext.data(),
                             static_cast<int>(ciphertext.size()))) {
    return operation_error(cx, "AES-GCM decryption failed");
  }
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_bytes),
                               tag.data())) {
    return operation_error(cx, "AES-GCM decryption failed");
  }
  int final_written = 0;
  if (1 != EVP_DecryptFinal_ex(ctx.get(), out.data() + written, &final_written)) {
    return operation_error(cx, "AES-GCM authentication failed");
  }
  out.resize(written + final_written);
  // 9. Return a new ArrayBuffer containing plaintext.
  return to_array_buffer(cx, out);
}

std::unique_ptr<CryptoAlgorithmAES_CBC>
CryptoAlgorithmAES_CBC::fromParameters(JSContext *cx, JS::HandleObject parameters) {
  auto result = std::make_unique<CryptoAlgorithmAES_CBC>();
  std::optional<std::vector<uint8_t>> iv;
  if (!buffer_member(cx, parameters, "AesCbcParams", "iv", true, &iv)) {
    return nullptr;
  }
  result->iv = std::move(iv.value());
  return result;
}

// https://w3c.github.io/webcrypto/#aes-cbc-operations, "encrypt"
JSObject *CryptoAlgorithmAES_CBC::encrypt(JSContext *cx, JS::HandleObject key,
                                          std::span<uint8_t> data) {
  // 1. If the iv member of normalizedAlgorithm does not have a length of 16
  // bytes, then throw an OperationError.
  if (iv.size() != AES_BLOCK) {
    return operation_error(cx, "AES-CBC iv must be 16 bytes");
  }
  auto key_data = CryptoKey::secretKeyData(key);
  const EVP_CIPHER *cipher = aes_cipher(CryptoAlgorithmIdentifier::AES_CBC, key_data.size());
  if (!cipher) {
    return operation_error(cx, "Invalid AES key length");
  }
  // 2. Let paddedPlaintext be the result of adding padding octets to plaintext
  // according to RFC 2315 Section 10.3, step 2.
  // 3. Let ciphertext be the result of performing the CBC Encryption operation.
  std::vector<uint8_t> out;
  if (!cipher_pass(cipher, true, key_data, iv, data, &out)) {
    return operation_error(cx, "AES-CBC encryption failed");
  }
  // 4. Return a new ArrayBuffer containing ciphertext.
  return to_array_buffer(cx, out);
}

// https://w3c.github.io/webcrypto/#aes-cbc-operations, "decrypt"
JSObject *CryptoAlgorithmAES_CBC::decrypt(JSContext *cx, JS::HandleObject key,
                                          std::span<uint8_t> data) {
  // 1. If the iv member of normalizedAlgorithm does not have a length of 16
  // bytes, then throw an OperationError.
  if (iv.size() != AES_BLOCK) {
    return operation_error(cx, "AES-CBC iv must be 16 bytes");
  }
  auto key_data = CryptoKey::secretKeyData(key);
  const EVP_CIPHER *cipher = aes_cipher(CryptoAlgorithmIdentifier::AES_CBC, key_data.size());
  if (!cipher) {
    return operation_error(cx, "Invalid AES key length");
  }
  // 2-6. Decrypt and remove the padding; bad padding is an OperationError.
  std::vector<uint8_t> out;
  if (!cipher_pass(cipher, false, key_data, iv, data, &out)) {
    return operation_error(cx, "AES-CBC decryption failed");
  }
  // 7. Return a new ArrayBuffer containing plaintext.
  return to_array_buffer(cx, out);
}

std::unique_ptr<CryptoAlgorithmAES_CTR>
CryptoAlgorithmAES_CTR::fromParameters(JSContext *cx, JS::HandleObject parameters) {
  auto result = std::make_unique<CryptoAlgorithmAES_CTR>();
  std::optional<std::vector<uint8_t>> counter;
  if (!buffer_member(cx, parameters, "AesCtrParams", "counter", true, &counter)) {
    return nullptr;
  }
  result->counter = std::move(counter.value());
  std::optional<double> length;
  if (!integer_member(cx, parameters, "AesCtrParams", "length", true, 255, &length)) {
    return nullptr;
  }
  result->length = static_cast<uint8_t>(length.value());
  return result;
}

// https://w3c.github.io/webcrypto/#aes-ctr-operations, "encrypt" (and
// "decrypt", which is the same operation).
JSObject *CryptoAlgorithmAES_CTR::encrypt(JSContext *cx, JS::HandleObject key,
                                          std::span<uint8_t> data) {
  // 1. If the counter member of normalizedAlgorithm does not have a length of
  // 16 bytes, then throw an OperationError.
  if (counter.size() != AES_BLOCK) {
    return operation_error(cx, "AES-CTR counter must be 16 bytes");
  }
  // 2. If the length member of normalizedAlgorithm is zero or is greater than
  // 128, then throw an OperationError.
  if (length == 0 || length > 128) {
    return operation_error(cx, "AES-CTR length must be between 1 and 128");
  }
  auto key_data = CryptoKey::secretKeyData(key);
  const EVP_CIPHER *cipher = aes_cipher(CryptoAlgorithmIdentifier::AES_CTR, key_data.size());
  if (!cipher) {
    return operation_error(cx, "Invalid AES key length");
  }

  // 3. Encrypt with the counter block's rightmost `length` bits as the
  // counter. That counter wraps around within those bits, where OpenSSL's
  // carries into the whole block, so the input is cut where the counter wraps
  // and the second part starts from a counter of zero. A counter that would
  // repeat a block is an OperationError.
  size_t blocks = (data.size() + AES_BLOCK - 1) / AES_BLOCK;
  // How many blocks remain before the counter wraps; SIZE_MAX stands for more
  // than any input can have.
  size_t until_wrap = SIZE_MAX;
  if (length < 64) {
    uint64_t low = 0;
    for (size_t i = 8; i < AES_BLOCK; i++) {
      low = (low << 8) | counter[i];
    }
    uint64_t mask = (uint64_t{1} << length) - 1;
    uint64_t space = mask + 1;
    if (blocks > space) {
      return operation_error(cx, "AES-CTR counter would repeat");
    }
    uint64_t remaining = space - (low & mask);
    if (remaining < SIZE_MAX) {
      until_wrap = static_cast<size_t>(remaining);
    }
  } else {
    // The counter has 64 bits or more; it can only wrap within this input if
    // every bit above its low 64 is already one.
    bool high_ones = true;
    for (size_t bit = 64; bit < length; bit++) {
      size_t byte = AES_BLOCK - 1 - bit / 8;
      if ((counter[byte] & (1 << (bit % 8))) == 0) {
        high_ones = false;
        break;
      }
    }
    uint64_t low = 0;
    for (size_t i = 8; i < AES_BLOCK; i++) {
      low = (low << 8) | counter[i];
    }
    if (high_ones && low != 0) {
      uint64_t remaining = ~low + 1;
      if (remaining < SIZE_MAX) {
        until_wrap = static_cast<size_t>(remaining);
      }
    }
  }

  std::vector<uint8_t> out;
  out.reserve(data.size() + AES_BLOCK);
  std::span<const uint8_t> input = data;
  if (blocks <= until_wrap) {
    if (!cipher_pass(cipher, true, key_data, counter, input, &out)) {
      return operation_error(cx, "AES-CTR encryption failed");
    }
  } else {
    size_t first = until_wrap * AES_BLOCK;
    std::vector<uint8_t> wrapped = counter;
    for (size_t bit = 0; bit < length; bit++) {
      wrapped[AES_BLOCK - 1 - bit / 8] &= static_cast<uint8_t>(~(1 << (bit % 8)));
    }
    if (!cipher_pass(cipher, true, key_data, counter, input.first(first), &out) ||
        !cipher_pass(cipher, true, key_data, wrapped, input.subspan(first), &out)) {
      return operation_error(cx, "AES-CTR encryption failed");
    }
  }
  // 4. Return a new ArrayBuffer containing ciphertext.
  return to_array_buffer(cx, out);
}

JSObject *CryptoAlgorithmAES_CTR::decrypt(JSContext *cx, JS::HandleObject key,
                                          std::span<uint8_t> data) {
  return encrypt(cx, key, data);
}

std::unique_ptr<CryptoAlgorithmGenerateKey>
CryptoAlgorithmGenerateKey::normalize(JSContext *cx, JS::HandleValue value) {
  auto identifierResult = normalizeIdentifier(cx, value);
  if (identifierResult.isErr()) {
    return nullptr;
  }
  auto identifier = identifierResult.unwrap();
  JS::RootedObject params(cx, parameters_object(cx, value));
  if (!params) {
    return nullptr;
  }

  switch (identifier) {
  case CryptoAlgorithmIdentifier::AES_CTR:
  case CryptoAlgorithmIdentifier::AES_CBC:
  case CryptoAlgorithmIdentifier::AES_GCM:
  case CryptoAlgorithmIdentifier::AES_KW:
    return CryptoAlgorithmAES_GenerateKey::fromParameters(cx, identifier, params);
  case CryptoAlgorithmIdentifier::HMAC:
    return CryptoAlgorithmHMAC_GenerateKey::fromParameters(cx, params);
  case CryptoAlgorithmIdentifier::RSASSA_PKCS1_v1_5:
  case CryptoAlgorithmIdentifier::RSA_PSS:
  case CryptoAlgorithmIdentifier::RSA_OAEP:
  case CryptoAlgorithmIdentifier::ECDSA:
  case CryptoAlgorithmIdentifier::ECDH:
    DOMException::raise(cx, "Supplied algorithm is not yet supported", "NotSupportedError");
    return nullptr;
  default:
    DOMException::raise(cx, "Supplied algorithm does not support the generateKey operation",
                        "NotSupportedError");
    return nullptr;
  }
}

std::unique_ptr<CryptoAlgorithmAES_GenerateKey>
CryptoAlgorithmAES_GenerateKey::fromParameters(JSContext *cx, CryptoAlgorithmIdentifier identifier,
                                               JS::HandleObject parameters) {
  std::optional<double> length;
  if (!integer_member(cx, parameters, "AesKeyGenParams", "length", true, 65535, &length)) {
    return nullptr;
  }
  return std::make_unique<CryptoAlgorithmAES_GenerateKey>(identifier,
                                                          static_cast<uint16_t>(length.value()));
}

// https://w3c.github.io/webcrypto/#aes-gcm-operations, "generate key"
JSObject *CryptoAlgorithmAES_GenerateKey::generateKey(JSContext *cx, bool extractable,
                                                      CryptoKeyUsages usages) {
  // 1. If usages contains any entry which is not one of "encrypt", "decrypt",
  // "wrapKey" or "unwrapKey", then throw a SyntaxError.
  if (!aes_usages_valid(identifier_, usages)) {
    DOMException::raise(cx, "Unsupported key usage for an AES key", "SyntaxError");
    return nullptr;
  }
  // 2. If the length member of normalizedAlgorithm is not equal to one of 128,
  // 192 or 256, then throw an OperationError.
  if (length != 128 && length != 192 && length != 256) {
    return operation_error(cx, "AES key length must be 128, 192 or 256 bits");
  }
  // 3. Generate an AES key of length equal to the length member of
  // normalizedAlgorithm.
  auto random = host_api::Random::get_bytes(length / 8);
  if (const auto *err = random.to_err()) {
    HANDLE_ERROR(cx, *err);
    return nullptr;
  }
  auto bytes = std::move(random.unwrap());
  // 5-12. A secret key whose algorithm is an AesKeyAlgorithm.
  JS::RootedObject algorithm(cx, aes_key_algorithm(cx, identifier_, length));
  if (!algorithm) {
    return nullptr;
  }
  return CryptoKey::createSecret(cx, algorithm, std::span<const uint8_t>(bytes.ptr.get(), bytes.len),
                                 extractable, usages);
}

std::unique_ptr<CryptoAlgorithmHMAC_GenerateKey>
CryptoAlgorithmHMAC_GenerateKey::fromParameters(JSContext *cx, JS::HandleObject parameters) {
  JS::RootedValue hash_val(cx);
  if (!JS_GetProperty(cx, parameters, "hash", &hash_val)) {
    return nullptr;
  }
  if (hash_val.isUndefined()) {
    api::throw_error(cx, api::Errors::TypeError, "crypto.subtle", "HmacKeyGenParams.hash",
                     "be present");
    return nullptr;
  }
  auto hash = toHashIdentifier(cx, hash_val);
  if (hash.isErr()) {
    return nullptr;
  }
  std::optional<double> length;
  if (!integer_member(cx, parameters, "HmacKeyGenParams", "length", false, 4294967295.0,
                      &length)) {
    return nullptr;
  }
  std::optional<uint32_t> bits;
  if (length.has_value()) {
    bits = static_cast<uint32_t>(length.value());
  }
  return std::make_unique<CryptoAlgorithmHMAC_GenerateKey>(hash.unwrap(), bits);
}

// https://w3c.github.io/webcrypto/#hmac-operations, "generate key"
JSObject *CryptoAlgorithmHMAC_GenerateKey::generateKey(JSContext *cx, bool extractable,
                                                       CryptoKeyUsages usages) {
  // 1. If usages contains any entry which is not "sign" or "verify", then throw
  // a SyntaxError.
  if ((usages.toInt() & ~(CryptoKeyUsages::sign_flag | CryptoKeyUsages::verify_flag)) != 0) {
    DOMException::raise(cx, "HMAC keys only support 'sign' and 'verify' operations",
                        "SyntaxError");
    return nullptr;
  }
  // 2. If the length member of normalizedAlgorithm is not present: let length
  // be the block size in bits of the hash function. Otherwise, if it is
  // non-zero: let length be equal to it. Otherwise: throw an OperationError.
  uint32_t bits = 0;
  if (!length.has_value()) {
    switch (hashIdentifier) {
    case CryptoAlgorithmIdentifier::SHA_1:
    case CryptoAlgorithmIdentifier::SHA_256:
      bits = 512;
      break;
    case CryptoAlgorithmIdentifier::SHA_384:
    case CryptoAlgorithmIdentifier::SHA_512:
      bits = 1024;
      break;
    default:
      return operation_error(cx, "Unsupported hash for an HMAC key");
    }
  } else if (length.value() != 0) {
    bits = length.value();
  } else {
    return operation_error(cx, "HMAC key length must not be zero");
  }
  // 3. Generate a key of length length bits.
  auto random = host_api::Random::get_bytes((bits + 7) / 8);
  if (const auto *err = random.to_err()) {
    HANDLE_ERROR(cx, *err);
    return nullptr;
  }
  auto bytes = std::move(random.unwrap());
  // 5-12. A secret key whose algorithm is an HmacKeyAlgorithm.
  CryptoAlgorithmHMAC_Import key_algorithm(hashIdentifier, bits);
  JS::RootedObject algorithm(cx, key_algorithm.toObject(cx));
  if (!algorithm) {
    return nullptr;
  }
  return CryptoKey::createSecret(cx, algorithm, std::span<const uint8_t>(bytes.ptr.get(), bytes.len),
                                 extractable, usages);
}

// https://w3c.github.io/webcrypto/#hmac-operations and
// https://w3c.github.io/webcrypto/#aes-gcm-operations, "export key"
JSObject *exportSecretKey(JSContext *cx, CryptoKeyFormat format, JS::HandleObject key) {
  MOZ_ASSERT(CryptoKey::type(key) == CryptoKeyType::Secret);
  auto data = CryptoKey::secretKeyData(key);

  // 2. If format is "raw": let data be the raw octets of the key, and result
  // a new ArrayBuffer containing data.
  if (format == CryptoKeyFormat::Raw) {
    return to_array_buffer(cx, data);
  }
  if (format != CryptoKeyFormat::Jwk) {
    DOMException::raise(cx, "Supplied format is not supported", "NotSupportedError");
    return nullptr;
  }

  // 3. If format is "jwk":
  JS::RootedObject algorithm(cx, CryptoKey::get_algorithm(key));
  JS::RootedValue name_val(cx);
  if (!JS_GetProperty(cx, algorithm, "name", &name_val)) {
    return nullptr;
  }
  auto name_chars = core::encode(cx, name_val);
  if (!name_chars) {
    return nullptr;
  }
  std::string_view name = name_chars;

  std::string alg;
  if (name == "HMAC") {
    JS::RootedValue hash_val(cx);
    if (!JS_GetProperty(cx, algorithm, "hash", &hash_val) || !hash_val.isObject()) {
      return nullptr;
    }
    JS::RootedObject hash(cx, &hash_val.toObject());
    JS::RootedValue hash_name_val(cx);
    if (!JS_GetProperty(cx, hash, "name", &hash_name_val)) {
      return nullptr;
    }
    auto hash_chars = core::encode(cx, hash_name_val);
    if (!hash_chars) {
      return nullptr;
    }
    std::string_view hash_name = hash_chars;
    if (hash_name == "SHA-1") {
      alg = "HS1";
    } else if (hash_name == "SHA-256") {
      alg = "HS256";
    } else if (hash_name == "SHA-384") {
      alg = "HS384";
    } else if (hash_name == "SHA-512") {
      alg = "HS512";
    } else {
      DOMException::raise(cx, "Unsupported hash for an HMAC key", "NotSupportedError");
      return nullptr;
    }
  } else {
    auto identifier = normalizeIdentifier(cx, name_val);
    if (identifier.isErr()) {
      return nullptr;
    }
    alg = "A" + std::to_string(data.size() * 8) + aes_jwk_suffix(identifier.unwrap());
  }

  // 3.1 Let jwk be a new JsonWebKey dictionary.
  // 3.2 Set the kty attribute of jwk to the string "oct".
  // 3.3 Set the k attribute of jwk to be a string containing data, encoded
  // according to Section 6.4 of JSON Web Algorithms [JWA] (base64url, no
  // padding).
  std::string k = base64::forgivingBase64Encode(
      std::string_view(reinterpret_cast<const char *>(data.data()), data.size()),
      base64::base64URLEncodeTable);
  while (!k.empty() && k.back() == '=') {
    k.pop_back();
  }
  JS::RootedObject jwk(cx, JS_NewPlainObject(cx));
  if (!jwk) {
    return nullptr;
  }
  auto set_string = [&](const char *member, std::string_view value) -> bool {
    JS::RootedString str(cx, JS_NewStringCopyN(cx, value.data(), value.size()));
    if (!str) {
      return false;
    }
    JS::RootedValue val(cx, JS::StringValue(str));
    return JS_SetProperty(cx, jwk, member, val);
  };
  if (!set_string("kty", "oct") || !set_string("k", k) || !set_string("alg", alg)) {
    return nullptr;
  }
  // 3.4 Set the key_ops attribute of jwk to the usages attribute of key.
  JS::RootedValue usages_val(cx);
  if (!JS_GetProperty(cx, key, "usages", &usages_val) || !usages_val.isObject()) {
    return nullptr;
  }
  JS::RootedObject usages(cx, &usages_val.toObject());
  uint32_t usages_len = 0;
  if (!JS::GetArrayLength(cx, usages, &usages_len)) {
    return nullptr;
  }
  JS::RootedObject key_ops(cx, JS::NewArrayObject(cx, usages_len));
  if (!key_ops) {
    return nullptr;
  }
  JS::RootedValue usage(cx);
  for (uint32_t i = 0; i < usages_len; i++) {
    if (!JS_GetElement(cx, usages, i, &usage) || !JS_SetElement(cx, key_ops, i, usage)) {
      return nullptr;
    }
  }
  JS::RootedValue key_ops_val(cx, JS::ObjectValue(*key_ops));
  if (!JS_SetProperty(cx, jwk, "key_ops", key_ops_val)) {
    return nullptr;
  }
  // 3.5 Set the ext attribute of jwk to the [[extractable]] internal slot of
  // key.
  JS::RootedValue ext_val(cx, JS::BooleanValue(CryptoKey::extractable(key)));
  if (!JS_SetProperty(cx, jwk, "ext", ext_val)) {
    return nullptr;
  }
  // 3.6 Let result be the result of converting jwk to an ECMAScript Object.
  return jwk;
}

} // namespace builtins::web::crypto
