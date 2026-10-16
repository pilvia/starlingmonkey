#include "fetch-api.h"
#include "builtin.h"
#include "encode.h"
#include "extension-api.h"
#include "fetch-utils.h"
#include "headers.h"
#include "mozilla/Assertions.h"
#include "mozilla/Utf8.h"
#include "mozilla/WeakPtr.h"
#include "request-response.h"

#include "../abort/abort-signal.h"
#include "../blob.h"
#include "../form-data/form-data.h"
#include "../url.h"

#include <fmt/format.h>

namespace builtins::web::fetch {

using abort::AbortAlgorithm;
using abort::AbortSignal;
using blob::Blob;
using fetch::Headers;
using host_api::HostString;

static api::Engine *ENGINE;

enum class FetchScheme : uint8_t {
  About,
  Blob,
  Data,
  File,
  Http,
  Https,
};

struct Terminator : AbortAlgorithm {
  mozilla::WeakPtr<ResponseFutureTask> task;

  Terminator(const mozilla::WeakPtr<ResponseFutureTask>& task) : task(task) {}

  bool run(JSContext *cx) override {
    if (auto *t = task.get()) {
      return t->abort(ENGINE);
    }
    return true;
  }
};

std::optional<FetchScheme> scheme_from_url(const std::string_view &url) {
  if (url.starts_with("about:")) {
    return FetchScheme::About;
  }
  if (url.starts_with("blob:")) {
    return FetchScheme::Blob;
  }
  if (url.starts_with("data:")) {
    return FetchScheme::Data;
  }
  if (url.starts_with("file:")) {
    return FetchScheme::File;
  }
  if (url.starts_with("http")) {
    return FetchScheme::Http;
  }
  if (url.starts_with("https")) {
    return FetchScheme::Https;
  }

  return std::nullopt;
}

// https://fetch.spec.whatwg.org/#concept-network-error
bool network_error(JSContext *cx, HandleObject response_promise, MutableHandleValue rval) {
  // A network error is a response whose type is "error", status is 0, status message is the empty
  // byte sequence, header list is « », body is null, and body info is a new response body info.
  RootedObject response_obj(cx, Response::create(cx));
  if (!response_obj) {
    return false;
  }

  Response::set_type(response_obj, Response::Type::Error);
  Response::set_status(response_obj, 0);
  Response::set_status_message_from_code(cx, response_obj, 0);

  JS::RootedValue result(cx);
  result.setObject(*response_obj);
  JS::ResolvePromise(cx, response_promise, result);

  return api::throw_error(cx, FetchErrors::FetchNetworkError);
}

bool fetch_https(JSContext *cx, HandleObject request_obj, HandleObject response_promise,
                 HostString method, HostString url) {
  unique_ptr<host_api::HttpHeaders> headers =
      RequestOrResponse::headers_handle_clone(cx, request_obj);
  if (!headers) {
    return false;
  }

  auto *request = host_api::HttpOutgoingRequest::make(method, std::move(url), std::move(headers));
  MOZ_RELEASE_ASSERT(request);
  JS_SetReservedSlot(request_obj, static_cast<uint32_t>(Request::Slots::Request),
                     PrivateValue(request));

  bool streaming = false;
  if (!RequestOrResponse::maybe_stream_body(cx, request_obj, request, &streaming)) {
    return false;
  }
  if (streaming) {
    // Ensure that the body handle is stored before making the request handle invalid by sending it.
    request->body();
  }

  host_api::FutureHttpIncomingResponse *pending_handle = nullptr;
  {
    auto res = request->send();
    if (const auto *err = res.to_err()) {
      HANDLE_ERROR(cx, *err);
      return false;
    }

    pending_handle = res.unwrap();
  }

  // If the request body is streamed, we need to wait for streaming to complete
  // before marking the request as pending.
  if (!streaming) {
    // TODO: what about non streaming?
    auto task = js::MakeUnique<ResponseFutureTask>(request_obj, pending_handle);
    auto weak = mozilla::WeakPtr<ResponseFutureTask>(task.get());
    ENGINE->queue_async_task(task.release());

    RootedObject signal(cx, Request::signal(request_obj));
    MOZ_ASSERT(signal);

    AbortSignal::add_algorithm(signal, js::MakeUnique<Terminator>(weak));
  }

  SetReservedSlot(request_obj, static_cast<uint32_t>(Request::Slots::ResponsePromise),
                  ObjectValue(*response_promise));
  SetReservedSlot(request_obj, static_cast<uint32_t>(Request::Slots::PendingResponseHandle),
                  PrivateValue(pending_handle));

  return true;
}

namespace {

constexpr int32_t MAX_REDIRECTS = 20;

bool is_redirect_status(uint16_t status) {
  return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

jsurl::SpecString spec_string(std::string_view str) {
  return jsurl::SpecString(reinterpret_cast<uint8_t *>(const_cast<char *>(str.data())),
                           str.size(), str.size());
}

std::string_view slice_view(jsurl::SpecSlice slice) {
  return {reinterpret_cast<const char *>(slice.data), slice.len};
}

std::string_view spec_view(const jsurl::SpecString &str) {
  return {reinterpret_cast<const char *>(str.data), str.len};
}

// A Location header is bytes. The URL parser takes UTF-8, so a value that isn't valid UTF-8 has
// its non-ASCII bytes percent-encoded first, which is what browsers do (whatwg/fetch#883).
std::string location_as_utf8(std::string_view bytes) {
  if (mozilla::IsUtf8(mozilla::Span(bytes.data(), bytes.size()))) {
    return std::string(bytes);
  }
  std::string out;
  out.reserve(bytes.size() * 3);
  for (unsigned char c : bytes) {
    if (c < 0x80) {
      out.push_back(static_cast<char>(c));
    } else {
      out += fmt::format("%{:02X}", c);
    }
  }
  return out;
}

struct UrlDeleter {
  void operator()(jsurl::JSUrl *url) const { jsurl::free_jsurl(url); }
};
using OwnedUrl = std::unique_ptr<jsurl::JSUrl, UrlDeleter>;

} // namespace

bool maybe_follow_redirect(JSContext *cx, HandleObject request,
                           host_api::HttpIncomingResponse *response, bool *followed) {
  *followed = false;

  auto status_res = response->status();
  if (status_res.is_err() || !is_redirect_status(status_res.unwrap())) {
    return true;
  }
  uint16_t status = status_res.unwrap();

  // Unlike a browser, which hands back an opaque-redirect filtered response, "manual" returns
  // the redirect response itself, as Node, Deno and workerd do: a server reads its Location.
  auto mode = Request::redirect_mode(request);
  if (mode == Request::RedirectMode::Manual) {
    return true;
  }

  // 3. Let locationURL be actualResponse's location URL given request's current URL's fragment.
  auto headers_res = response->headers();
  if (headers_res.is_err()) {
    return true;
  }
  auto location_res = headers_res.unwrap()->get("location");
  if (location_res.is_err()) {
    return true;
  }
  auto location_values = std::move(location_res.unwrap());
  // 4. If locationURL is null, then return response.
  if (!location_values.has_value() || location_values->empty()) {
    return true;
  }
  // A header list with more than one Location doesn't parse as a single URL: failure.
  if (location_values->size() > 1) {
    return api::throw_error(cx, FetchErrors::FetchNetworkError);
  }

  RootedValue current_url_val(cx, RequestOrResponse::url(request));
  auto current_url = core::encode(cx, current_url_val);
  if (!current_url) {
    return false;
  }
  auto base_str = spec_string(std::string_view(current_url));
  OwnedUrl base(jsurl::new_jsurl(&base_str));
  if (!base) {
    return api::throw_error(cx, FetchErrors::FetchNetworkError);
  }
  auto location_utf8 = location_as_utf8(std::string_view(location_values->front()));
  auto location_str = spec_string(location_utf8);
  OwnedUrl location(jsurl::new_jsurl_with_base(&location_str, base.get()));
  // 5. If locationURL is failure, then return a network error.
  if (!location) {
    return api::throw_error(cx, FetchErrors::FetchNetworkError);
  }

  // 6. If locationURL's scheme is not an HTTP(S) scheme, then return a network error.
  auto scheme = slice_view(jsurl::protocol(location.get()));
  if (scheme != "http:" && scheme != "https:") {
    return api::throw_error(cx, FetchErrors::FetchNetworkError);
  }

  // Step 4 of main fetch: "error" turns any redirect into a network error.
  if (mode == Request::RedirectMode::Error) {
    return api::throw_error(cx, FetchErrors::FetchNetworkError);
  }

  // 7. If request's redirect count is 20, then return a network error.
  // 8. Increase request's redirect count by 1.
  int32_t count =
      JS::GetReservedSlot(request, std::to_underlying(Request::Slots::RedirectCount)).toInt32();
  if (count >= MAX_REDIRECTS) {
    return api::throw_error(cx, FetchErrors::FetchNetworkError);
  }
  JS::SetReservedSlot(request, std::to_underlying(Request::Slots::RedirectCount),
                      JS::Int32Value(count + 1));

  // 11. If internalResponse's status is not 303, request's body is non-null, and request's
  // body's source is null, then return a network error.
  RootedValue body_source(
      cx, JS::GetReservedSlot(request, std::to_underlying(Request::Slots::BodySource)));
  bool has_body = RequestOrResponse::has_body(request);
  if (status != 303 && has_body && body_source.isUndefined()) {
    return api::throw_error(cx, FetchErrors::FetchNetworkError);
  }

  RootedObject headers(cx, RequestOrResponse::headers(cx, request));
  if (!headers) {
    return false;
  }

  // 12. If one of the following is true
  //   * internalResponse's status is 301 or 302 and request's method is `POST`
  //   * internalResponse's status is 303 and request's method is not `GET` or `HEAD`
  // then set request's method to `GET` and request's body to null, and remove every
  // request-body-header name from request's header list.
  RootedString method_str(cx, Request::method(request));
  auto method = core::encode(cx, method_str);
  if (!method) {
    return false;
  }
  std::string_view method_view = method;
  if (((status == 301 || status == 302) && method_view == "POST") ||
      (status == 303 && method_view != "GET" && method_view != "HEAD")) {
    method_str = JS_AtomizeString(cx, "GET");
    if (!method_str) {
      return false;
    }
    JS::SetReservedSlot(request, std::to_underlying(Request::Slots::Method),
                        JS::StringValue(method_str));
    method = core::encode(cx, method_str);
    if (!method) {
      return false;
    }
    has_body = false;
    JS::SetReservedSlot(request, std::to_underlying(Request::Slots::HasBody), JS::FalseValue());
    JS::SetReservedSlot(request, std::to_underlying(Request::Slots::BodyStream), JS::NullValue());
    JS::SetReservedSlot(request, std::to_underlying(Request::Slots::BodySource),
                        JS::UndefinedValue());
    for (auto name : {"content-encoding", "content-language", "content-location", "content-type",
                      "content-length"}) {
      if (!Headers::remove_valid(cx, headers, name)) {
        return false;
      }
    }
  }

  // 13. If request's current URL's origin is not same origin with locationURL's origin, then for
  // each headerName of CORS non-wildcard request-header name, delete headerName from request's
  // header list. That is `Authorization`; like Node and Deno we also drop the other credentials
  // a server-side caller sets by hand, `Cookie` and `Proxy-Authorization`.
  auto base_origin = jsurl::origin(base.get());
  auto location_origin = jsurl::origin(location.get());
  if (spec_view(base_origin) != spec_view(location_origin) ||
      spec_view(base_origin) == "null") {
    for (auto name : {"authorization", "cookie", "proxy-authorization"}) {
      if (!Headers::remove_valid(cx, headers, name)) {
        return false;
      }
    }
  }

  // 14. If request's body is non-null, then set request's body to the body of the result of
  // safely extracting request's body's source.
  if (has_body) {
    JS::SetReservedSlot(request, std::to_underlying(Request::Slots::HasBody), JS::FalseValue());
    JS::SetReservedSlot(request, std::to_underlying(Request::Slots::BodyUsed), JS::FalseValue());
    JS::SetReservedSlot(request, std::to_underlying(Request::Slots::BodyStream), JS::NullValue());
    // A FormData is serialized with a fresh boundary, so its Content-Type is derived again.
    if (body_source.isObject() && form_data::FormData::is_instance(&body_source.toObject()) &&
        !Headers::remove_valid(cx, headers, "content-type")) {
      return false;
    }
    if (!Headers::remove_valid(cx, headers, "content-length") ||
        !RequestOrResponse::extract_body(cx, request, body_source)) {
      return false;
    }
  }

  // 19-20. Append locationURL to request's URL list and fetch again.
  auto href = slice_view(jsurl::href(location.get()));
  RootedString href_str(cx, JS_NewStringCopyUTF8N(cx, JS::UTF8Chars(href.data(), href.size())));
  if (!href_str) {
    return false;
  }
  RootedValue href_val(cx, JS::StringValue(href_str));
  RequestOrResponse::set_url(request, href_val);
  HostString url = core::encode(cx, href_val);
  if (!url) {
    return false;
  }

  RootedObject response_promise(cx, Request::response_promise(request));
  if (!fetch_https(cx, request, response_promise, std::move(method), std::move(url))) {
    return false;
  }

  *followed = true;
  return true;
}

/// https://fetch.spec.whatwg.org/#scheme-fetch
bool fetch_blob(JSContext *cx, HandleObject request_obj, HandleObject response_promise,
                HostString method, HostString url, MutableHandleValue rval) {
  // 1. Let blobURLEntry be request's current URL's blob URL entry.
  RootedString blob_url(cx);

  // 2. If request's method is not `GET` or blobURLEntry is null, then return a network error.
  if (std::memcmp(method.ptr.get(), "GET", method.len) != 0) {
    return network_error(cx, response_promise, rval);
  }

  // 3. Let requestEnvironment be the result of determining the environment given request.
  // 4. Let isTopLevelNavigation be true if request's destination is "document"; otherwise, false.
  // 5. If isTopLevelNavigation is false and requestEnvironment is null, then return a network
  // error.
  // 6. Let navigationOrEnvironment be the string "navigation" if isTopLevelNavigation is true;
  //  otherwise, requestEnvironment.
  //  N/A
  // 7. Let blob be the result of obtaining a blob object given blobURLEntry and
  // navigationOrEnvironment.
  std::string url_key(url.ptr.get());
  RootedObject blob(cx, url::URL::getObjectURL(url_key));

  // 8. If blob is not a Blob object, then return a network error.
  if (!blob || !Blob::is_instance(blob)) {
    return network_error(cx, response_promise, rval);
  }

  // 9. Let response be a new response.
  RootedObject response_obj(cx, Response::create(cx));
  if (!response_obj) {
    return false;
  }

  // 10. Let fullLength be blob's size.
  auto full_len = Blob::blob_size(blob);
  // 11. Let serializedFullLength be fullLength, serialized and isomorphic encoded.
  // 12. Let type be blob's type.
  RootedString type(cx, Blob::type(blob));

  JS::RootedObject req_headers(cx, RequestOrResponse::headers(cx, request_obj));
  if (!req_headers) {
    return false;
  }

  auto maybe_range_index = Headers::lookup(cx, req_headers, "Range");

  // 13. If request's header list does not contain `Range`:
  if (!maybe_range_index.has_value()) {
    // 1. Let bodyWithType be the result of safely extracting blob.
    RootedValue body_val(cx, JS::ObjectValue(*blob));
    RootedValue init_val(cx);
    if (!Response::initialize(cx, response_obj, body_val, init_val)) {
      return false;
    }

    // 2. Set response's status message to `OK`.
    Response::set_status_message_from_code(cx, response_obj, 200);

    // 3. Set response's body to bodyWithType's body.
    // 4. Set response's header list to (`Content-Length`, serializedFullLength), (`Content-Type`, type).
    // 3 and 4 done at the end.
    // 14. Otherwise:
  } else {
    // 1. Set response's range-requested flag.
    // 2. Let rangeHeader be the result of getting `Range` from request's header list.
    // 3. Let rangeValue be the result of parsing a single range header value given rangeHeader and
    // true.
    // 4. If rangeValue is failure, then return a network error.
    auto *headers = Headers::get_index(cx, req_headers, maybe_range_index.value());
    MOZ_ASSERT(headers);

    const auto &[key, val] = *headers;
    std::string_view range_query(val);

    // 5 and 6 see extract_range function
    auto maybe_range = extract_range(range_query, full_len);
    if (!maybe_range.has_value()) {
      return network_error(cx, response_promise, rval);
    }

    const auto [start_range, end_range] = maybe_range.value();

    // 8. Let slicedBlob be the result of invoking slice blob given blob, rangeStart, rangeEnd + 1,
    // and type.
    // 9. Let slicedBodyWithType be the result of safely extracting slicedBlob.
    // 10. Set response's body to slicedBodyWithType's body.
    // 11. Let serializedSlicedLength be slicedBlob's size, serialized and isomorphic encoded.

    /// TODO: fix blob API so that we can pass start,end values directly
    JS::Value vp[4];
    vp[2].setInt32(start_range);
    vp[3].setInt32(end_range + 1);
    auto args = CallArgsFromVp(2, vp);

    RootedValue sliced_blob_val(cx);
    if (!Blob::slice(cx, blob, args, &sliced_blob_val)) {
      return false;
    }

    RootedValue init_val(cx);
    if (!Response::initialize(cx, response_obj, sliced_blob_val, init_val)) {
      return false;
    }

    // 12. Let contentRange be the result of invoking build a content range given rangeStart,
    // rangeEnd, and fullLength.
    // 13. Set response's status to 206.
    // 14. Set response's status message to `Partial Content`.
    Response::set_status(response_obj, 206);
    Response::set_status_message_from_code(cx, response_obj, 206);
    // 15. Set response's header list to  (`Content-Length`, serializedSlicedLength),
    // (`Content-Type`, type), (`Content-Range`, contentRange).

    JS::RootedObject resp_headers(cx, RequestOrResponse::headers(cx, response_obj));
    if (!resp_headers) {
      return false;
    }

    auto content_range_str = fmt::format("bytes {}-{}/{}", start_range, end_range, full_len);
    if (!Headers::set_valid_if_undefined(cx, resp_headers, "Content-Range", content_range_str)) {
      return false;
    }

    // overwrite full_len with sliced blob length so it's written to headers
    full_len = Blob::blob_size(&sliced_blob_val.toObject());
  }

  JS::RootedObject resp_headers(cx, RequestOrResponse::headers(cx, response_obj));
  if (!resp_headers) {
    return false;
  }

  auto full_len_str = std::to_string(full_len);
  if (!Headers::set_valid_if_undefined(cx, resp_headers, "Content-Length", full_len_str)) {
    return false;
  }

  auto chars = core::encode(cx, type);
  if (!chars) {
    return false;
  }

  const auto *type_str = (JS::GetStringLength(type) != 0U) ? chars.ptr.get() : "";
  if (!Headers::set_valid_if_undefined(cx, resp_headers, "Content-Type", type_str)) {
    return false;
  }

  // Blob response type is "basic"
  Response::set_type(response_obj, Response::Type::Basic);

  // 15. Return response.
  JS::RootedValue result(cx);
  result.setObject(*response_obj);
  JS::ResolvePromise(cx, response_promise, result);

  return true;
}

// TODO: throw in all Request methods/getters that rely on host calls once a
// request has been sent. The host won't let us act on them anymore anyway.
/**
 * The `fetch` global function
 * https://fetch.spec.whatwg.org/#fetch-method
 */
bool fetch(JSContext *cx, unsigned argc, Value *vp) {
  CallArgs args = CallArgsFromVp(argc, vp);

  REQUEST_HANDLER_ONLY("fetch")

  if (!args.requireAtLeast(cx, "fetch", 1)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 1. Let p be a new promise.
  RootedObject response_promise(cx, JS::NewPromiseObject(cx, nullptr));
  if (!response_promise) {
    return false;
  }

  args.rval().setObject(*response_promise);

  // 2. Let requestObject be the result of invoking the initial value of Request as constructor
  // with input and init as arguments. If this throws an exception, reject p with it and return p.
  RootedObject request_obj(cx, Request::create(cx));
  if (!request_obj) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 3. Let request be requestObject's request.
  if (!Request::initialize(cx, request_obj, args[0], args.get(1), Headers::HeadersGuard::Request)) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  // 4. If requestObject's signal is aborted, then:
  RootedObject signal(cx, Request::signal(request_obj));
  MOZ_ASSERT(signal);

  if (AbortSignal::is_aborted(signal)) {
    // 1. Abort the fetch() call with p, request, null, and requestObject's signal's abort reason.
    RootedValue error(cx, AbortSignal::reason(signal));
    abort_fetch(cx, response_promise, request_obj, nullptr, error);
    // 2. Return p.
    // (already set in args.rval())
    return true;
  }

  RootedString method_str(cx, Request::method(request_obj));
  HostString method = core::encode(cx, method_str);
  if (!method.ptr) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  RootedValue url_val(cx, RequestOrResponse::url(request_obj));
  HostString url = core::encode(cx, url_val);
  if (!url.ptr) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }

  switch (scheme_from_url(url).value_or(FetchScheme::Https)) {
  case FetchScheme::Blob: {
    auto res = fetch_blob(cx, request_obj, response_promise, std::move(method), std::move(url),
                          args.rval());
    if (!res) {
      return ReturnPromiseRejectedWithPendingError(cx, args);
    }
    break;
  }
  case FetchScheme::Http:
  case FetchScheme::Https:
  default: {
    auto res = fetch_https(cx, request_obj, response_promise, std::move(method), std::move(url));
    if (!res) {
      return ReturnPromiseRejectedWithPendingError(cx, args);
    }
    break;
  }
  }

  return true;
}

const JSFunctionSpec methods[] = {JS_FN("fetch", fetch, 2, JSPROP_ENUMERATE), JS_FS_END};

bool install(api::Engine *engine) {
  ENGINE = engine;

  if (!JS_DefineFunctions(engine->cx(), engine->global(), methods)) {
    return false;
  }
  if (!request_response::install(engine)) {
    return false;
  }
  if (!Headers::init_class(engine->cx(), engine->global())) {
    return false;
  }
  return true;
}

} // namespace builtins::web::fetch
