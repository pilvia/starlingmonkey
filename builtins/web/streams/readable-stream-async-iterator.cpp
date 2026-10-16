// ReadableStream's async iteration: `values()` and `[Symbol.asyncIterator]()`.
// https://streams.spec.whatwg.org/#rs-asynciterator
// https://webidl.spec.whatwg.org/#es-asynchronous-iterator-prototype-object
//
// The streams themselves are SpiderMonkey's; this adds the WebIDL async
// iterator on top of their reader API.
#include "readable-stream-async-iterator.h"

#include "js/Stream.h"

namespace builtins::web::streams {

namespace {

enum Slots : uint8_t {
  // The ReadableStream being iterated.
  Stream,
  // Its default reader, acquired by values().
  Reader,
  // A boolean: values({ preventCancel }).
  PreventCancel,
  // The ongoing promise, or undefined.
  OngoingPromise,
  // A boolean: the iterator's "is finished".
  Finished,
  SlotCount,
};

const JSClass iterator_class = {"ReadableStream AsyncIterator",
                                JSCLASS_HAS_RESERVED_SLOTS(SlotCount), nullptr};

// The asynchronous iterator prototype object: next() and return() on top of
// %AsyncIteratorPrototype%, and nothing else (no constructor).
JS::PersistentRooted<JSObject *> iterator_proto;

bool is_iterator(JS::HandleValue value) {
  return value.isObject() && JS::GetClass(&value.toObject()) == &iterator_class;
}

JSObject *iter_result(JSContext *cx, JS::HandleValue value, bool done) {
  JS::RootedObject result(cx, JS_NewPlainObject(cx));
  if (!result) {
    return nullptr;
  }
  JS::RootedValue done_val(cx, JS::BooleanValue(done));
  if (!JS_DefineProperty(cx, result, "value", value, JSPROP_ENUMERATE) ||
      !JS_DefineProperty(cx, result, "done", done_val, JSPROP_ENUMERATE)) {
    return nullptr;
  }
  return result;
}

JSObject *resolved_promise(JSContext *cx, JS::HandleValue value) {
  return JS::CallOriginalPromiseResolve(cx, value);
}

JSObject *rejected_with_pending_error(JSContext *cx) {
  return PromiseRejectedWithPendingError(cx);
}

void release_reader(JSContext *cx, JS::HandleObject iter) {
  JS::RootedObject reader(cx, &JS::GetReservedSlot(iter, Reader).toObject());
  // Releasing an already released reader is not an error worth surfacing.
  if (!JS::ReadableStreamReaderReleaseLock(cx, reader)) {
    JS_ClearPendingException(cx);
  }
}

// The reader's read() fulfilled with a { value, done } result.
bool next_fulfilled(JSContext *cx, JS::HandleObject iter, JS::HandleValue, JS::CallArgs args) {
  // Set object's ongoing promise to null.
  JS::SetReservedSlot(iter, OngoingPromise, JS::UndefinedValue());

  JS::RootedValue value(cx);
  bool done = false;
  if (args.get(0).isObject()) {
    JS::RootedObject read_result(cx, &args.get(0).toObject());
    JS::RootedValue done_val(cx);
    if (!JS_GetProperty(cx, read_result, "done", &done_val) ||
        !JS_GetProperty(cx, read_result, "value", &value)) {
      return false;
    }
    done = JS::ToBoolean(done_val);
  }

  JS::RootedObject result(cx);
  if (done) {
    // close steps: release the reader and resolve with end of iteration.
    // If next is end of iteration: set object's is finished to true and return
    // CreateIterResultObject(undefined, true).
    release_reader(cx, iter);
    JS::SetReservedSlot(iter, Finished, JS::TrueValue());
    result = iter_result(cx, JS::UndefinedHandleValue, true);
  } else {
    // chunk steps: return CreateIterResultObject(next, false).
    result = iter_result(cx, value, false);
  }
  if (!result) {
    return false;
  }
  args.rval().setObject(*result);
  return true;
}

// The reader's read() rejected: the stream errored.
bool next_rejected(JSContext *cx, JS::HandleObject iter, JS::HandleValue, JS::CallArgs args) {
  // error steps: release the reader. Then set object's ongoing promise to
  // null, set object's is finished to true, and throw reason.
  release_reader(cx, iter);
  JS::SetReservedSlot(iter, OngoingPromise, JS::UndefinedValue());
  JS::SetReservedSlot(iter, Finished, JS::TrueValue());
  JS_SetPendingException(cx, args.get(0));
  return false;
}

// https://webidl.spec.whatwg.org/#es-asynchronous-iterator-prototype-object,
// next(), "nextSteps".
JSObject *next_steps(JSContext *cx, JS::HandleObject iter) {
  // If object's is finished is true: return a promise resolved with
  // CreateIterResultObject(undefined, true).
  if (JS::GetReservedSlot(iter, Finished).toBoolean()) {
    JS::RootedValue result(cx);
    JSObject *obj = iter_result(cx, JS::UndefinedHandleValue, true);
    if (!obj) {
      return nullptr;
    }
    result.setObject(*obj);
    return resolved_promise(cx, result);
  }

  // Let nextPromise be the result of getting the next iteration result:
  // a read request on the reader.
  JS::RootedObject reader(cx, &JS::GetReservedSlot(iter, Reader).toObject());
  JS::RootedObject read_promise(cx, JS::ReadableStreamDefaultReaderRead(cx, reader));
  if (!read_promise) {
    return rejected_with_pending_error(cx);
  }

  JS::RootedObject on_fulfilled(cx, create_internal_method<next_fulfilled>(cx, iter));
  JS::RootedObject on_rejected(cx, create_internal_method<next_rejected>(cx, iter));
  if (!on_fulfilled || !on_rejected) {
    return nullptr;
  }
  // Perform PerformPromiseThen(nextPromise, onFulfilled, onRejected,
  // nextPromiseCapability).
  return JS::CallOriginalPromiseThen(cx, read_promise, on_fulfilled, on_rejected);
}

bool run_next_steps(JSContext *cx, JS::HandleObject iter, JS::HandleValue, JS::CallArgs args) {
  JSObject *promise = next_steps(cx, iter);
  if (!promise) {
    return false;
  }
  args.rval().setObject(*promise);
  return true;
}

// next()
bool next(JSContext *cx, unsigned argc, JS::Value *vp) {
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  // If object is not a platform object of the right type, return a promise
  // rejected with a TypeError.
  if (!is_iterator(args.thisv())) {
    api::throw_error(cx, api::Errors::WrongReceiver, "next", "ReadableStream AsyncIterator");
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  JS::RootedObject iter(cx, &args.thisv().toObject());

  // Let ongoingPromise be object's ongoing promise. If it is not null, chain
  // nextSteps after it (on fulfillment and rejection alike); otherwise run
  // nextSteps now. Either way the result becomes the ongoing promise.
  JS::RootedObject promise(cx);
  JS::RootedValue ongoing(cx, JS::GetReservedSlot(iter, OngoingPromise));
  if (ongoing.isObject()) {
    JS::RootedObject ongoing_promise(cx, &ongoing.toObject());
    JS::RootedObject steps(cx, create_internal_method<run_next_steps>(cx, iter));
    if (!steps) {
      return false;
    }
    promise = JS::CallOriginalPromiseThen(cx, ongoing_promise, steps, steps);
  } else {
    promise = next_steps(cx, iter);
  }
  if (!promise) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  JS::SetReservedSlot(iter, OngoingPromise, JS::ObjectValue(*promise));
  args.rval().setObject(*promise);
  return true;
}

// https://streams.spec.whatwg.org/#rs-asynciterator-prototype-return, run as
// WebIDL's "returnSteps". `value` is return()'s argument.
JSObject *return_steps(JSContext *cx, JS::HandleObject iter, JS::HandleValue value) {
  // If object's is finished is true: return a promise resolved with
  // CreateIterResultObject(value, true).
  if (JS::GetReservedSlot(iter, Finished).toBoolean()) {
    JS::RootedValue result(cx);
    JSObject *obj = iter_result(cx, value, true);
    if (!obj) {
      return nullptr;
    }
    result.setObject(*obj);
    return resolved_promise(cx, result);
  }
  // Set object's is finished to true.
  JS::SetReservedSlot(iter, Finished, JS::TrueValue());

  // The asynchronous iterator return: unless preventCancel, cancel the stream
  // with `value` and release the reader, returning the cancel's promise.
  if (!JS::GetReservedSlot(iter, PreventCancel).toBoolean()) {
    JS::RootedObject stream(cx, &JS::GetReservedSlot(iter, Stream).toObject());
    JS::RootedObject cancel_promise(cx, JS::ReadableStreamCancel(cx, stream, value));
    release_reader(cx, iter);
    if (!cancel_promise) {
      return rejected_with_pending_error(cx);
    }
    return cancel_promise;
  }
  release_reader(cx, iter);
  return resolved_promise(cx, JS::UndefinedHandleValue);
}

bool run_return_steps(JSContext *cx, JS::HandleObject iter, JS::HandleValue value,
                      JS::CallArgs args) {
  JSObject *promise = return_steps(cx, iter, value);
  if (!promise) {
    return false;
  }
  args.rval().setObject(*promise);
  return true;
}

// The fulfillment of returnPromise: CreateIterResultObject(value, true).
bool return_fulfilled(JSContext *cx, JS::HandleObject, JS::HandleValue value, JS::CallArgs args) {
  JSObject *result = iter_result(cx, value, true);
  if (!result) {
    return false;
  }
  args.rval().setObject(*result);
  return true;
}

// return(value)
bool return_(JSContext *cx, unsigned argc, JS::Value *vp) {
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  if (!is_iterator(args.thisv())) {
    api::throw_error(cx, api::Errors::WrongReceiver, "return", "ReadableStream AsyncIterator");
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  JS::RootedObject iter(cx, &args.thisv().toObject());
  JS::RootedValue value(cx, args.get(0));

  // If ongoingPromise is not null, chain returnSteps after it; otherwise run
  // returnSteps now. The result becomes the ongoing promise, so a next() that
  // follows waits for the return.
  JS::RootedObject return_promise(cx);
  JS::RootedValue ongoing(cx, JS::GetReservedSlot(iter, OngoingPromise));
  if (ongoing.isObject()) {
    JS::RootedObject ongoing_promise(cx, &ongoing.toObject());
    JS::RootedObject steps(cx, create_internal_method<run_return_steps>(cx, iter, value, 1));
    if (!steps) {
      return false;
    }
    return_promise = JS::CallOriginalPromiseThen(cx, ongoing_promise, steps, steps);
  } else {
    return_promise = return_steps(cx, iter, value);
  }
  if (!return_promise) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  JS::SetReservedSlot(iter, OngoingPromise, JS::ObjectValue(*return_promise));

  // Return the result of reacting to returnPromise with fulfillSteps.
  JS::RootedObject on_fulfilled(cx, create_internal_method<return_fulfilled>(cx, iter, value));
  if (!on_fulfilled) {
    return false;
  }
  JS::RootedObject result(cx,
                          JS::CallOriginalPromiseThen(cx, return_promise, on_fulfilled, nullptr));
  if (!result) {
    return ReturnPromiseRejectedWithPendingError(cx, args);
  }
  args.rval().setObject(*result);
  return true;
}

// ReadableStream.prototype.values(options), also its [Symbol.asyncIterator].
// https://streams.spec.whatwg.org/#rs-get-iterator
bool values(JSContext *cx, unsigned argc, JS::Value *vp) {
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  if (!args.thisv().isObject() || !JS::IsReadableStream(&args.thisv().toObject())) {
    return api::throw_error(cx, api::Errors::WrongReceiver, "values", "ReadableStream");
  }
  JS::RootedObject stream(cx, &args.thisv().toObject());

  // ReadableStreamIteratorOptions: undefined, null or an object.
  bool prevent_cancel = false;
  JS::HandleValue options = args.get(0);
  if (options.isObject()) {
    JS::RootedObject options_obj(cx, &options.toObject());
    JS::RootedValue prevent_cancel_val(cx);
    if (!JS_GetProperty(cx, options_obj, "preventCancel", &prevent_cancel_val)) {
      return false;
    }
    prevent_cancel = JS::ToBoolean(prevent_cancel_val);
  } else if (!options.isNullOrUndefined()) {
    return api::throw_error(cx, api::Errors::TypeError, "ReadableStream.values", "options",
                            "be an object");
  }

  // 1. Let reader be ? AcquireReadableStreamDefaultReader(stream).
  JS::RootedObject reader(
      cx, JS::ReadableStreamGetReader(cx, stream, JS::ReadableStreamReaderMode::Default));
  if (!reader) {
    return false;
  }

  // 2. Set iterator's reader to reader.
  // 3. Let preventCancel be args[0]["preventCancel"].
  // 4. Set iterator's prevent cancel to preventCancel.
  JS::RootedObject iter(cx, JS_NewObjectWithGivenProto(cx, &iterator_class, iterator_proto));
  if (!iter) {
    return false;
  }
  JS::SetReservedSlot(iter, Stream, JS::ObjectValue(*stream));
  JS::SetReservedSlot(iter, Reader, JS::ObjectValue(*reader));
  JS::SetReservedSlot(iter, PreventCancel, JS::BooleanValue(prevent_cancel));
  JS::SetReservedSlot(iter, OngoingPromise, JS::UndefinedValue());
  JS::SetReservedSlot(iter, Finished, JS::FalseValue());
  args.rval().setObject(*iter);
  return true;
}

const JSFunctionSpec iterator_methods[] = {
    JS_FN("next", next, 0, JSPROP_ENUMERATE),
    JS_FN("return", return_, 1, JSPROP_ENUMERATE),
    JS_FS_END,
};

const JSPropertySpec iterator_properties[] = {
    JS_STRING_SYM_PS(toStringTag, "ReadableStream AsyncIterator", JSPROP_READONLY),
    JS_PS_END,
};

} // namespace

bool ReadableStreamAsyncIterator::install(JSContext *cx, JS::HandleObject global) {
  JS::RootedObject async_iterator_proto(cx, JS::GetRealmAsyncIteratorPrototype(cx));
  if (!async_iterator_proto) {
    return false;
  }
  iterator_proto.init(cx, JS_NewObjectWithGivenProto(cx, nullptr, async_iterator_proto));
  if (!iterator_proto || !JS_DefineFunctions(cx, iterator_proto, iterator_methods) ||
      !JS_DefineProperties(cx, iterator_proto, iterator_properties)) {
    return false;
  }

  JS::RootedValue ctor_val(cx);
  if (!JS_GetProperty(cx, global, "ReadableStream", &ctor_val) || !ctor_val.isObject()) {
    return false;
  }
  JS::RootedObject ctor(cx, &ctor_val.toObject());
  JS::RootedValue proto_val(cx);
  if (!JS_GetProperty(cx, ctor, "prototype", &proto_val) || !proto_val.isObject()) {
    return false;
  }
  JS::RootedObject proto(cx, &proto_val.toObject());

  // values() is an enumerable method; [Symbol.asyncIterator] is the same
  // function object, not enumerable.
  JSFunction *values_fn = JS_DefineFunction(cx, proto, "values", values, 0, JSPROP_ENUMERATE);
  if (!values_fn) {
    return false;
  }
  JS::RootedValue values_val(cx, JS::ObjectValue(*JS_GetFunctionObject(values_fn)));
  JS::RootedId async_iterator_id(
      cx, JS::PropertyKey::Symbol(JS::GetWellKnownSymbol(cx, JS::SymbolCode::asyncIterator)));
  return JS_DefinePropertyById(cx, proto, async_iterator_id, values_val, 0);
}

} // namespace builtins::web::streams
