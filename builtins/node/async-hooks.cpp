// `node:async_hooks`: AsyncLocalStorage, in the subset that the runtimes other than Node agree
// on (https://github.com/wintercg/proposal-common-minimum-api/blob/main/asynclocalstorage.md):
// `run`, `exit`, `getStore`, and the static `bind` and `snapshot`. `enterWith`, `disable` and
// the rest of `async_hooks` are left out, as they are there.
//
// The class is also a global, as in Vercel's Edge Runtime: React's edge server renderer
// (`react-dom/server.edge`) looks for `AsyncLocalStorage` on the global, not in a module, to
// find the render a resource hint such as `preload()` belongs to after an await.
//
// An instance is a key in the engine's async context (api::AsyncContext), and its store is the
// value that key has in the current context. The engine carries the context into promise
// reactions and timers, so a store set by `run` is the store of everything `run`'s callback
// starts, across any number of awaits.

#include "builtin.h"
#include "extension-api.h"

namespace builtins::node::async_hooks {

class AsyncLocalStorage : public BuiltinImpl<AsyncLocalStorage> {
  static bool run(JSContext *cx, unsigned argc, JS::Value *vp);
  static bool exit(JSContext *cx, unsigned argc, JS::Value *vp);
  static bool getStore(JSContext *cx, unsigned argc, JS::Value *vp);
  static bool bind(JSContext *cx, unsigned argc, JS::Value *vp);
  static bool snapshot(JSContext *cx, unsigned argc, JS::Value *vp);

public:
  static constexpr const char *class_name = "AsyncLocalStorage";
  static constexpr unsigned ctor_length = 0;

  enum class Slots : uint8_t { Count };

  static const JSFunctionSpec static_methods[];
  static const JSPropertySpec static_properties[];
  static const JSFunctionSpec methods[];
  static const JSPropertySpec properties[];

  static bool constructor(JSContext *cx, unsigned argc, JS::Value *vp);
};

namespace {

// Calls `callback` with `this_val` and `argv` while `context` is the current async context.
bool call_in(JSContext *cx, HandleObject context, HandleValue this_val, HandleValue callback,
             const HandleValueArray &argv, MutableHandleValue rval) {
  api::AsyncContext::AutoEnter enter(cx, context);
  return JS::Call(cx, this_val, callback, argv, rval);
}

bool require_callable(JSContext *cx, HandleValue value, const char *method) {
  if (value.isObject() && JS::IsCallable(&value.toObject())) {
    return true;
  }
  return api::throw_error(cx, api::Errors::TypeError, method, "the callback", "be a function");
}

// The function `AsyncLocalStorage.snapshot()` returns: `(fn, ...args)` runs `fn(...args)` in
// the context the snapshot was taken in.
bool run_in_snapshot(JSContext *cx, HandleObject context, HandleValue, CallArgs args) {
  if (!args.requireAtLeast(cx, "runInAsyncScope", 1) ||
      !require_callable(cx, args[0], "runInAsyncScope")) {
    return false;
  }
  return call_in(cx, context, args.thisv(), args[0],
                 HandleValueArray::subarray(args, 1, args.length() - 1), args.rval());
}

// The function `AsyncLocalStorage.bind(fn)` returns: calls `fn` with its own `this` and
// arguments in the context `bind` was called in.
bool run_bound(JSContext *cx, HandleObject context, HandleValue callback, CallArgs args) {
  return call_in(cx, context, args.thisv(), callback, args, args.rval());
}

} // namespace

const JSFunctionSpec AsyncLocalStorage::static_methods[] = {
    JS_FN("bind", bind, 1, JSPROP_ENUMERATE),
    JS_FN("snapshot", snapshot, 0, JSPROP_ENUMERATE),
    JS_FS_END,
};

const JSPropertySpec AsyncLocalStorage::static_properties[] = {
    JS_PS_END,
};

const JSFunctionSpec AsyncLocalStorage::methods[] = {
    JS_FN("run", run, 2, JSPROP_ENUMERATE),
    JS_FN("exit", exit, 1, JSPROP_ENUMERATE),
    JS_FN("getStore", getStore, 0, JSPROP_ENUMERATE),
    JS_FS_END,
};

const JSPropertySpec AsyncLocalStorage::properties[] = {
    JS_STRING_SYM_PS(toStringTag, "AsyncLocalStorage", JSPROP_READONLY),
    JS_PS_END,
};

// run(store, callback, ...args): `callback(...args)` with `store` as this instance's store.
bool AsyncLocalStorage::run(JSContext *cx, unsigned argc, JS::Value *vp) {
  METHOD_HEADER(2);
  if (!require_callable(cx, args[1], "AsyncLocalStorage.run")) {
    return false;
  }
  RootedObject current(cx, api::AsyncContext::current());
  RootedObject context(cx, api::AsyncContext::with_value(cx, current, self, args[0]));
  if (!context) {
    return false;
  }
  return call_in(cx, context, JS::UndefinedHandleValue, args[1],
                 HandleValueArray::subarray(args, 2, args.length() - 2), args.rval());
}

// exit(callback, ...args): `callback(...args)` with no store for this instance.
bool AsyncLocalStorage::exit(JSContext *cx, unsigned argc, JS::Value *vp) {
  METHOD_HEADER(1);
  if (!require_callable(cx, args[0], "AsyncLocalStorage.exit")) {
    return false;
  }
  RootedObject current(cx, api::AsyncContext::current());
  RootedObject context(cx, api::AsyncContext::without_value(cx, current, self));
  if (!context) {
    return false;
  }
  return call_in(cx, context, JS::UndefinedHandleValue, args[0],
                 HandleValueArray::subarray(args, 1, args.length() - 1), args.rval());
}

// getStore(): this instance's store in the current context, or undefined.
bool AsyncLocalStorage::getStore(JSContext *cx, unsigned argc, JS::Value *vp) {
  METHOD_HEADER(0);
  if (!api::AsyncContext::lookup(api::AsyncContext::current(), self, args.rval())) {
    args.rval().setUndefined();
  }
  return true;
}

// AsyncLocalStorage.bind(fn): `fn`, bound to the current context.
bool AsyncLocalStorage::bind(JSContext *cx, unsigned argc, JS::Value *vp) {
  CallArgs args = CallArgsFromVp(argc, vp);
  if (!args.requireAtLeast(cx, "AsyncLocalStorage.bind", 1) ||
      !require_callable(cx, args[0], "AsyncLocalStorage.bind")) {
    return false;
  }
  RootedObject context(cx, api::AsyncContext::current());
  JSObject *bound = create_internal_method<run_bound>(cx, context, args[0], 0, "bound");
  if (!bound) {
    return false;
  }
  args.rval().setObject(*bound);
  return true;
}

// AsyncLocalStorage.snapshot(): a function that runs a callback in the current context.
bool AsyncLocalStorage::snapshot(JSContext *cx, unsigned argc, JS::Value *vp) {
  CallArgs args = CallArgsFromVp(argc, vp);
  RootedObject context(cx, api::AsyncContext::current());
  JSObject *runner = create_internal_method<run_in_snapshot>(cx, context, JS::UndefinedHandleValue,
                                                             1, "runInAsyncScope");
  if (!runner) {
    return false;
  }
  args.rval().setObject(*runner);
  return true;
}

bool AsyncLocalStorage::constructor(JSContext *cx, unsigned argc, JS::Value *vp) {
  CTOR_HEADER("AsyncLocalStorage", 0);
  RootedObject self(cx, JS_NewObjectForConstructor(cx, &class_, args));
  if (!self) {
    return false;
  }
  args.rval().setObject(*self);
  return true;
}

bool install(api::Engine *engine) {
  JSContext *cx = engine->cx();

  // JS_InitClass defines the constructor as a non-enumerable property, and a builtin module
  // exports its object's enumerable properties, so the class is set up on a scratch object
  // and then defined on the module.
  RootedObject scratch(cx, JS_NewPlainObject(cx));
  if (!scratch || !AsyncLocalStorage::init_class_impl(cx, scratch)) {
    return false;
  }
  RootedValue ctor(cx);
  if (!JS_GetProperty(cx, scratch, AsyncLocalStorage::class_name, &ctor)) {
    return false;
  }

  RootedObject module(cx, JS_NewPlainObject(cx));
  if (!module) {
    return false;
  }
  RootedValue module_val(cx, JS::ObjectValue(*module));
  if (!JS_DefineProperty(cx, module, AsyncLocalStorage::class_name, ctor, JSPROP_ENUMERATE) ||
      // `import async_hooks from "node:async_hooks"` as well as the named import.
      !JS_DefineProperty(cx, module, "default", module_val, JSPROP_ENUMERATE)) {
    return false;
  }

  return engine->define_builtin_module("node:async_hooks", module_val) &&
         engine->define_builtin_module("async_hooks", module_val) &&
         // Like the other classes on the global: writable, configurable, not enumerable.
         JS_DefineProperty(cx, engine->global(), AsyncLocalStorage::class_name, ctor, 0);
}

} // namespace builtins::node::async_hooks
