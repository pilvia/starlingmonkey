#include "subtle-crypto.h"
#include "../dom-exception.h"
#include "builtin.h"
#include "encode.h"

#include <vector>

namespace builtins::web::crypto {

using dom_exception::DOMException;

// digest(algorithm, data)
// https://w3c.github.io/webcrypto/#SubtleCrypto-method-digest
bool SubtleCrypto::digest(JSContext *cx, unsigned argc, JS::Value *vp) {
  JS::CallArgs args = CallArgsFromVp(argc, vp);
  if (!check_receiver(cx, args.thisv(), "SubtleCrypto.digest")) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  if (!args.requireAtLeast(cx, "SubtleCrypto.digest", 2)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 1. Let algorithm be the algorithm parameter passed to the digest() method.
  auto algorithm = args.get(0);

  // 2 . Let data be the result of getting a copy of the bytes held by the data parameter
  // passed to the digest() method.
  auto data = value_to_buffer(cx, args.get(1), "SubtleCrypto.digest: data");
  if (!data.has_value()) {
    // value_to_buffer would have already created a JS exception so we don't need to create one
    // ourselves.
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 3. Let normalizedAlgorithm be the result of normalizing an algorithm, with alg set to
  // algorithm and op set to "digest".
  // 4. If an error occurred, return a Promise rejected with normalizedAlgorithm.
  auto normalizedAlgorithm = CryptoAlgorithmDigest::normalize(cx, algorithm);
  if (!normalizedAlgorithm) {
    // TODO Rename error to NotSupportedError
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 5. Let promise be a new Promise.
  JS::RootedObject promise(cx, JS::NewPromiseObject(cx, nullptr));
  if (!promise) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 6. Return promise and perform the remaining steps in parallel.
  args.rval().setObject(*promise);

  // 7. If the following steps or referenced procedures say to throw an error, reject promise with
  // the returned error and then terminate the algorithm.
  // 8. Let result be the result of performing the digest operation specified by normalizedAlgorithm
  // using algorithm, with data as message.
  auto *array_buffer = normalizedAlgorithm->digest(cx, data.value());
  if (!array_buffer) {
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 9. Resolve promise with result.
  JS::RootedValue result(cx);
  result.setObject(*array_buffer);
  JS::ResolvePromise(cx, promise, result);

  return true;
}

//  Promise<CryptoKey> importKey(KeyFormat format,
//                         (BufferSource or JsonWebKey) keyData,
//                         AlgorithmIdentifier algorithm,
//                         boolean extractable,
//                         sequence<KeyUsage> keyUsages );
// https://w3c.github.io/webcrypto/#dfn-SubtleCrypto-method-importKey
bool SubtleCrypto::importKey(JSContext *cx, unsigned argc, JS::Value *vp) {
  MOZ_ASSERT(cx);
  JS::CallArgs args = CallArgsFromVp(argc, vp);

  if (!args.requireAtLeast(cx, "SubtleCrypto.importKey", 5)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  if (!check_receiver(cx, args.thisv(), "SubtleCrypto.importKey")) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 1. Let format, algorithm, extractable and usages, be the format, algorithm,
  // extractable and keyUsages parameters passed to the importKey() method, respectively.
  CryptoKeyFormat format;
  {
    auto format_arg = args.get(0);
    // Convert into a String following https://tc39.es/ecma262/#sec-tostring
    auto format_chars = core::encode(cx, format_arg);
    if (!format_chars.ptr) {
      return ReturnPromiseRejectedWithPendingError(cx, args);
    }
    std::string_view format_string = format_chars;
    if (format_string == "spki") {
      format = CryptoKeyFormat::Spki;
    } else if (format_string == "pkcs8") {
      format = CryptoKeyFormat::Pkcs8;
    } else if (format_string == "jwk") {
      format = CryptoKeyFormat::Jwk;
    } else if (format_string == "raw") {
      format = CryptoKeyFormat::Raw;
    } else {
      DOMException::raise(cx,
        "crypto.subtle.importkey: Provided format parameter is not supported. "
          "Supported formats are: 'spki', 'pkcs8', 'jwk', and 'raw'",
        "NotSupportedError");
      return ReturnPromiseRejectedWithPendingError(cx, args);
    }
  }
  auto key_data = args.get(1);
  auto algorithm = args.get(2);
  bool extractable = JS::ToBoolean(args.get(3));
  CryptoKeyUsages usages;
  {
    auto usages_arg = args.get(4);

    auto keyUsageMaskResult = CryptoKeyUsages::from(cx, usages_arg);
    if (keyUsageMaskResult.isErr()) {
      return ReturnPromiseRejectedWithPendingError(cx, args);
    }
    usages = keyUsageMaskResult.unwrap();
  }

  // 3. Let normalizedAlgorithm be the result of normalizing an algorithm, with alg set to algorithm
  // and op set to "importKey".
  // 4. If an error occurred, return a Promise rejected with normalizedAlgorithm.
  auto normalizedAlgorithm = CryptoAlgorithmImportKey::normalize(cx, algorithm);
  if (!normalizedAlgorithm) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 5. Let promise be a new Promise.
  JS::RootedObject promise(cx, JS::NewPromiseObject(cx, nullptr));
  if (!promise) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 6. Return promise and perform the remaining steps in parallel.
  args.rval().setObject(*promise);

  // 7. If the following steps or referenced procedures say to throw an error,
  // reject promise with the returned error and then terminate the algorithm.

  // Steps 8 - 11 are all done in the `importKey` call
  // 8. Let result be the CryptoKey object that results from performing the
  // import key operation specified by normalizedAlgorithm using keyData,
  // algorithm, format, extractable and usages.
  // 9. If the [[type]] internal slot of result is "secret" or "private" and
  // usages is empty, then throw a SyntaxError.
  // 10. Set the [[extractable]] internal slot of result to extractable.
  // 11. Set the [[usages]] internal slot of result to the normalized value of
  // usages.
  JS::RootedObject result(cx);
  JSObject *key = normalizedAlgorithm->importKey(cx, format, key_data, extractable, usages);
  if (!key) {
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 12. Resolve promise with result.
  JS::RootedValue result_val(cx);
  result_val.setObject(*key);
  JS::ResolvePromise(cx, promise, result_val);

  return true;
}

// https://w3c.github.io/webcrypto/#SubtleCrypto-method-sign
bool SubtleCrypto::sign(JSContext *cx, unsigned argc, JS::Value *vp) {
  MOZ_ASSERT(cx);
  MOZ_ASSERT(vp);
  JS::CallArgs args = CallArgsFromVp(argc, vp);

  if (!args.requireAtLeast(cx, "SubtleCrypto.sign", 3)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  if (!check_receiver(cx, args.thisv(), "SubtleCrypto.sign")) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 1. Let algorithm and key be the algorithm and key parameters passed to the sign() method,
  // respectively.
  auto algorithm = args.get(0);
  auto key_arg = args.get(1);
  if (!CryptoKey::is_instance(key_arg)) {
    api::throw_error(cx, api::Errors::TypeError, "crypto.subtle.sign", "key",
      "be a CryptoKey object");
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  JS::RootedObject key(cx, &key_arg.toObject());

  // 2. Let data be the result of getting a copy of the bytes held by the data parameter passed to
  // the sign() method.
  std::optional<std::span<uint8_t>> dataOptional =
      value_to_buffer(cx, args.get(2), "crypto.subtle.sign: data");
  if (!dataOptional.has_value()) {
    // value_to_buffer would have already created a JS exception so we don't need to create one
    // ourselves.
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  std::span<uint8_t> data = dataOptional.value();

  // 3. Let normalizedAlgorithm be the result of normalizing an algorithm, with alg set to algorithm
  // and op set to "sign".
  auto normalizedAlgorithm = CryptoAlgorithmSignVerify::normalize(cx, algorithm);
  // 4. If an error occurred, return a Promise rejected with normalizedAlgorithm.
  if (!normalizedAlgorithm) {
    // TODO Rename error to NotSupportedError
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 5. Let promise be a new Promise.
  JS::RootedObject promise(cx, JS::NewPromiseObject(cx, nullptr));
  if (!promise) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  // 6. Return promise and perform the remaining steps in parallel.
  args.rval().setObject(*promise);

  // 7. If the following steps or referenced procedures say to throw an error, reject promise with
  // the returned error and then terminate the algorithm.

  // 8. If the name member of normalizedAlgorithm is not equal to the name attribute of the
  // [[algorithm]] internal slot of key then throw an InvalidAccessError.
  auto identifier = normalizedAlgorithm->identifier();
  auto match_result = CryptoKey::is_algorithm(cx, key, identifier);
  if (match_result.isErr()) {
    DOMException::raise(cx, "CryptoKey doesn't match AlgorithmIdentifier", "InvalidAccessError");
    return RejectPromiseWithPendingError(cx, promise);
  }

  if (match_result.unwrap() == false) {
    DOMException::raise(cx, "CryptoKey doesn't match AlgorithmIdentifier", "InvalidAccessError");
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 9. If the [[usages]] internal slot of key does not contain an entry that is "sign", then throw
  // an InvalidAccessError.
  if (!CryptoKey::canSign(key)) {
    DOMException::raise(cx, "CryptoKey doesn't support signing", "InvalidAccessError");
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 10. Let result be the result of performing the sign operation specified by normalizedAlgorithm
  // using key and algorithm and with data as message.
  auto *signature = normalizedAlgorithm->sign(cx, key, data);
  if (!signature) {
    return RejectPromiseWithPendingError(cx, promise);
  }
  JS::RootedValue result(cx, JS::ObjectValue(*signature));

  // 11. Resolve promise with result.
  JS::ResolvePromise(cx, promise, result);
  return true;
}

// Promise<any> verify(AlgorithmIdentifier algorithm,
//                     CryptoKey key,
//                     BufferSource signature,
//                     BufferSource data);
// https://w3c.github.io/webcrypto/#SubtleCrypto-method-verify
bool SubtleCrypto::verify(JSContext *cx, unsigned argc, JS::Value *vp) {
  MOZ_ASSERT(cx);
  MOZ_ASSERT(vp);
  JS::CallArgs args = CallArgsFromVp(argc, vp);

  if (!args.requireAtLeast(cx, "SubtleCrypto.verify", 4)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  if (!check_receiver(cx, args.thisv(), "SubtleCrypto.verify")) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 1. Let algorithm and key be the algorithm and key parameters passed to the verify() method,
  // respectively.
  auto algorithm = args.get(0);
  auto key_arg = args.get(1);
  if (!CryptoKey::is_instance(key_arg)) {
    api::throw_error(cx, api::Errors::TypeError, "crypto.subtle.verify", "key",
      "be a CryptoKey object");
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  JS::RootedObject key(cx, &key_arg.toObject());

  // 2. Let signature be the result of getting a copy of the bytes held by the signature
  // parameter passed to the verify() method.
  std::optional<std::span<uint8_t>> signature =
      value_to_buffer(cx, args.get(2), "SubtleCrypto.verify: signature (argument 3)");
  if (!signature) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 3. Let data be the result of getting a copy of the bytes held by the data parameter passed
  // to the verify() method.
  std::optional<std::span<uint8_t>> data =
      value_to_buffer(cx, args.get(3), "SubtleCrypto.verify: data (argument 4)");
  if (!data) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 4. Let normalizedAlgorithm be the result of normalizing an algorithm, with alg set to
  // algorithm and op set to "verify".
  // 5. If an error occurred, return a Promise rejected with normalizedAlgorithm.
  auto normalizedAlgorithm = CryptoAlgorithmSignVerify::normalize(cx, algorithm);
  if (!normalizedAlgorithm) {
    // TODO Rename error to NotSupportedError
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 6. Let promise be a new Promise.
  JS::RootedObject promise(cx, JS::NewPromiseObject(cx, nullptr));
  if (!promise) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 7. Return promise and perform the remaining steps in parallel.
  args.rval().setObject(*promise);

  // 8. If the following steps or referenced procedures say to throw an error, reject promise
  // with the returned error and then terminate the algorithm.
  // 9. If the name member of normalizedAlgorithm is not equal to the name attribute of the
  // [[algorithm]] internal slot of key then throw an InvalidAccessError.
  auto identifier = normalizedAlgorithm->identifier();
  auto match_result = CryptoKey::is_algorithm(cx, key, identifier);
  if (match_result.isErr() || match_result.unwrap() == false) {
    DOMException::raise(cx, "CryptoKey doesn't match AlgorithmIdentifier", "InvalidAccessError");
    return RejectPromiseWithPendingError(cx, promise);
  }
  // 10. If the [[usages]] internal slot of key does not contain an entry that is "verify", then
  // throw an InvalidAccessError.
  if (!CryptoKey::canVerify(key)) {
    DOMException::raise(cx, "CryptoKey doesn't support verification", "InvalidAccessError");
    return RejectPromiseWithPendingError(cx, promise);
  }
  // 11. Let result be the result of performing the verify operation specified by
  // normalizedAlgorithm using key, algorithm and signature and with data as message.

  auto matchResult = normalizedAlgorithm->verify(cx, key, signature.value(), data.value());
  if (matchResult.isErr()) {
    return RejectPromiseWithPendingError(cx, promise);
  }
  // 12. Resolve promise with result.
  JS::RootedValue result(cx);
  result.setBoolean(matchResult.unwrap());
  JS::ResolvePromise(cx, promise, result);

  return true;
}

namespace {

// encrypt(algorithm, key, data) and decrypt(algorithm, key, data) share every
// step but the usage they check and the operation they run.
// https://w3c.github.io/webcrypto/#SubtleCrypto-method-encrypt
// https://w3c.github.io/webcrypto/#SubtleCrypto-method-decrypt
bool encrypt_or_decrypt(JSContext *cx, unsigned argc, JS::Value *vp, bool encrypt) {
  JS::CallArgs args = CallArgsFromVp(argc, vp);
  const char *method = encrypt ? "SubtleCrypto.encrypt" : "SubtleCrypto.decrypt";
  if (!args.requireAtLeast(cx, method, 3)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  if (!SubtleCrypto::check_receiver(cx, args.thisv(), method)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 1. Let algorithm and key be the algorithm and key parameters passed to the
  // method, respectively.
  auto algorithm = args.get(0);
  auto key_arg = args.get(1);
  if (!CryptoKey::is_instance(key_arg)) {
    api::throw_error(cx, api::Errors::TypeError, method, "key", "be a CryptoKey object");
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  JS::RootedObject key(cx, &key_arg.toObject());

  // The data argument is a BufferSource: a value of another type is a
  // TypeError at conversion, before any step runs.
  const char *data_desc = encrypt ? "SubtleCrypto.encrypt: data" : "SubtleCrypto.decrypt: data";
  if (!value_to_buffer(cx, args.get(2), data_desc).has_value()) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 2. Let normalizedAlgorithm be the result of normalizing an algorithm, with
  // alg set to algorithm and op set to "encrypt" or "decrypt".
  // 3. If an error occurred, return a Promise rejected with normalizedAlgorithm.
  auto normalizedAlgorithm = CryptoAlgorithmEncryptDecrypt::normalize(cx, algorithm);
  if (!normalizedAlgorithm) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 4. Let data be the result of getting a copy of the bytes held by the data
  // parameter passed to the method. After normalization on purpose: a getter
  // on the algorithm may have changed or transferred the buffer.
  auto data = value_to_buffer(cx, args.get(2), data_desc);
  if (!data.has_value()) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  std::vector<uint8_t> bytes(data->begin(), data->end());

  // 5. Let promise be a new Promise.
  JS::RootedObject promise(cx, JS::NewPromiseObject(cx, nullptr));
  if (!promise) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  // 6. Return promise and perform the remaining steps in parallel.
  args.rval().setObject(*promise);

  // 8. If the name member of normalizedAlgorithm is not equal to the name
  // attribute of the [[algorithm]] internal slot of key then throw an
  // InvalidAccessError.
  auto match_result = CryptoKey::is_algorithm(cx, key, normalizedAlgorithm->identifier());
  if (match_result.isErr() || !match_result.unwrap()) {
    DOMException::raise(cx, "CryptoKey doesn't match AlgorithmIdentifier", "InvalidAccessError");
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 9. If the [[usages]] internal slot of key does not contain an entry that is
  // "encrypt" (or "decrypt"), then throw an InvalidAccessError.
  auto usages = CryptoKey::usages(key);
  if (encrypt ? !usages.canEncrypt() : !usages.canDecrypt()) {
    DOMException::raise(cx,
                        encrypt ? "CryptoKey doesn't support encryption"
                                : "CryptoKey doesn't support decryption",
                        "InvalidAccessError");
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 10. Let result be the result of performing the operation specified by
  // normalizedAlgorithm using algorithm and key and with data as plaintext (or
  // ciphertext).
  JSObject *result = encrypt ? normalizedAlgorithm->encrypt(cx, key, bytes)
                             : normalizedAlgorithm->decrypt(cx, key, bytes);
  if (!result) {
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 11. Resolve promise with result.
  JS::RootedValue result_val(cx, JS::ObjectValue(*result));
  JS::ResolvePromise(cx, promise, result_val);
  return true;
}

} // namespace

bool SubtleCrypto::encrypt(JSContext *cx, unsigned argc, JS::Value *vp) {
  return encrypt_or_decrypt(cx, argc, vp, true);
}

bool SubtleCrypto::decrypt(JSContext *cx, unsigned argc, JS::Value *vp) {
  return encrypt_or_decrypt(cx, argc, vp, false);
}

// Promise<(CryptoKey or CryptoKeyPair)> generateKey(AlgorithmIdentifier algorithm,
//                                                    boolean extractable,
//                                                    sequence<KeyUsage> keyUsages);
// https://w3c.github.io/webcrypto/#SubtleCrypto-method-generateKey
bool SubtleCrypto::generateKey(JSContext *cx, unsigned argc, JS::Value *vp) {
  JS::CallArgs args = CallArgsFromVp(argc, vp);
  if (!args.requireAtLeast(cx, "SubtleCrypto.generateKey", 3)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  if (!check_receiver(cx, args.thisv(), "SubtleCrypto.generateKey")) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 1. Let algorithm, extractable and usages be the algorithm, extractable and
  // keyUsages parameters passed to the generateKey() method, respectively.
  auto algorithm = args.get(0);
  bool extractable = JS::ToBoolean(args.get(1));
  auto usages_result = CryptoKeyUsages::from(cx, args.get(2));
  if (usages_result.isErr()) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  auto usages = usages_result.unwrap();

  // 2. Let normalizedAlgorithm be the result of normalizing an algorithm, with
  // alg set to algorithm and op set to "generateKey".
  // 3. If an error occurred, return a Promise rejected with normalizedAlgorithm.
  auto normalizedAlgorithm = CryptoAlgorithmGenerateKey::normalize(cx, algorithm);
  if (!normalizedAlgorithm) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 4. Let promise be a new Promise.
  JS::RootedObject promise(cx, JS::NewPromiseObject(cx, nullptr));
  if (!promise) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  // 5. Return promise and perform the remaining steps in parallel.
  args.rval().setObject(*promise);

  // 7. Let result be the result of performing the generate key operation
  // specified by normalizedAlgorithm using algorithm, extractable and usages.
  JS::RootedObject result(cx, normalizedAlgorithm->generateKey(cx, extractable, usages));
  if (!result) {
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 8. If result is a CryptoKey object: if the [[type]] internal slot of result
  // is "secret" or "private" and usages is empty, then throw a SyntaxError.
  if (CryptoKey::is_instance(result) && CryptoKey::type(result) != CryptoKeyType::Public &&
      usages.isEmpty()) {
    DOMException::raise(cx, "A secret or private key needs at least one usage", "SyntaxError");
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 10. Resolve promise with result.
  JS::RootedValue result_val(cx, JS::ObjectValue(*result));
  JS::ResolvePromise(cx, promise, result_val);
  return true;
}

// Promise<(ArrayBuffer or JsonWebKey)> exportKey(KeyFormat format, CryptoKey key);
// https://w3c.github.io/webcrypto/#SubtleCrypto-method-exportKey
bool SubtleCrypto::exportKey(JSContext *cx, unsigned argc, JS::Value *vp) {
  JS::CallArgs args = CallArgsFromVp(argc, vp);
  if (!args.requireAtLeast(cx, "SubtleCrypto.exportKey", 2)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  if (!check_receiver(cx, args.thisv(), "SubtleCrypto.exportKey")) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 1. Let format and key be the format and key parameters passed to the
  // exportKey() method, respectively. Both are WebIDL conversions, so a value
  // outside the KeyFormat enum or a non-CryptoKey is a TypeError.
  CryptoKeyFormat format;
  {
    auto format_chars = core::encode(cx, args.get(0));
    if (!format_chars.ptr) {
      return ReturnPromiseRejectedWithPendingError(cx, args);
    }
    std::string_view format_string = format_chars;
    if (format_string == "raw") {
      format = CryptoKeyFormat::Raw;
    } else if (format_string == "jwk") {
      format = CryptoKeyFormat::Jwk;
    } else if (format_string == "spki") {
      format = CryptoKeyFormat::Spki;
    } else if (format_string == "pkcs8") {
      format = CryptoKeyFormat::Pkcs8;
    } else {
      api::throw_error(cx, api::Errors::TypeError, "SubtleCrypto.exportKey", "format",
                       "be one of 'raw', 'spki', 'pkcs8' or 'jwk'");
      return ReturnPromiseRejectedWithPendingError(cx, args);
    }
  }
  auto key_arg = args.get(1);
  if (!CryptoKey::is_instance(key_arg)) {
    api::throw_error(cx, api::Errors::TypeError, "SubtleCrypto.exportKey", "key",
                     "be a CryptoKey object");
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  JS::RootedObject key(cx, &key_arg.toObject());

  // 2. Let promise be a new Promise.
  JS::RootedObject promise(cx, JS::NewPromiseObject(cx, nullptr));
  if (!promise) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  // 3. Return promise and perform the remaining steps in parallel.
  args.rval().setObject(*promise);

  // 5. If the name member of the [[algorithm]] internal slot of key does not
  // identify a registered algorithm that supports the export key operation,
  // then throw a NotSupportedError. Exporting is built for the secret keys
  // (HMAC and AES) so far.
  if (CryptoKey::type(key) != CryptoKeyType::Secret) {
    DOMException::raise(cx, "Exporting this key type is not yet supported", "NotSupportedError");
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 6. If the [[extractable]] internal slot of key is false, then throw an
  // InvalidAccessError.
  if (!CryptoKey::extractable(key)) {
    DOMException::raise(cx, "CryptoKey is not extractable", "InvalidAccessError");
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 7. Let result be the result of performing the export key operation
  // specified by the [[algorithm]] internal slot of key using key and format.
  JS::RootedObject result(cx, exportSecretKey(cx, format, key));
  if (!result) {
    return RejectPromiseWithPendingError(cx, promise);
  }

  // 8. Resolve promise with result.
  JS::RootedValue result_val(cx, JS::ObjectValue(*result));
  JS::ResolvePromise(cx, promise, result_val);
  return true;
}

const JSFunctionSpec SubtleCrypto::static_methods[] = {
    JS_FS_END,
};

const JSPropertySpec SubtleCrypto::static_properties[] = {
    JS_PS_END,
};

const JSFunctionSpec SubtleCrypto::methods[] = {
    JS_FN("encrypt", encrypt, 3, JSPROP_ENUMERATE),
    JS_FN("decrypt", decrypt, 3, JSPROP_ENUMERATE),
    JS_FN("sign", sign, 3, JSPROP_ENUMERATE),
    JS_FN("verify", verify, 4, JSPROP_ENUMERATE),
    JS_FN("digest", digest, 2, JSPROP_ENUMERATE),
    JS_FN("generateKey", generateKey, 3, JSPROP_ENUMERATE),
    JS_FN("importKey", importKey, 5, JSPROP_ENUMERATE),
    JS_FN("exportKey", exportKey, 2, JSPROP_ENUMERATE),
    JS_FS_END};

const JSPropertySpec SubtleCrypto::properties[] = {
    JS_STRING_SYM_PS(toStringTag, "SubtleCrypto", JSPROP_READONLY), JS_PS_END};

bool SubtleCrypto::init_class(JSContext *cx, JS::HandleObject global) {
  return init_class_impl(cx, global);
}
} // namespace builtins::web::crypto
