// The async context, and the job queue that carries it from a promise reaction's registration
// to its run. See `api::AsyncContext` in extension-api.h.

#include "extension-api.h"

#include "js/GCVector.h"
#include "js/Prefs.h"
#include "js/Promise.h"
#include "jsfriendapi.h"

#include <utility>

namespace {

// A frame binds or unbinds one key on top of its parent context. The empty context is the one
// frame with neither a key nor a parent.
enum class FrameSlots : uint8_t { Parent, Key, Value, Bound, Count };

const JSClass frame_class = {
    "AsyncContextFrame",
    JSCLASS_HAS_RESERVED_SLOTS(std::to_underlying(FrameSlots::Count)),
};

JS::PersistentRootedObject EMPTY;
JS::PersistentRootedObject CURRENT;

JSObject *frame_object(JSObject *frame, FrameSlots slot) {
  return JS::GetReservedSlot(frame, std::to_underlying(slot)).toObjectOrNull();
}

JSObject *new_frame(JSContext *cx, JS::HandleObject parent, JS::HandleObject key,
                    JS::HandleValue value, bool bound) {
  JSObject *frame = JS_NewObjectWithGivenProto(cx, &frame_class, nullptr);
  if (!frame) {
    return nullptr;
  }
  JS::SetReservedSlot(frame, std::to_underlying(FrameSlots::Parent),
                      JS::ObjectOrNullValue(parent));
  JS::SetReservedSlot(frame, std::to_underlying(FrameSlots::Key), JS::ObjectOrNullValue(key));
  JS::SetReservedSlot(frame, std::to_underlying(FrameSlots::Value), value);
  JS::SetReservedSlot(frame, std::to_underlying(FrameSlots::Bound), JS::BooleanValue(bound));
  return frame;
}

bool is_frame(JSObject *obj) { return obj && JS::GetClass(obj) == &frame_class; }

// SpiderMonkey's own job queue, but with the async context of each job. A reaction to a pending
// promise gets its host defined data, which is the context `getHostDefinedData` returned, when
// it is registered; SpiderMonkey hands it back here when the reaction is enqueued. A job without
// one is enqueued by the very operation that created it (a reaction to a settled promise, a
// thenable's job), so the current context is that operation's.
//
// This needs SpiderMonkey's legacy job path (`use_js_microtask_queue` off): on the JS microtask
// queue, a reaction to an already settled promise keeps no host defined data and reaches the
// embedding only when it runs, by which time the context it was registered in is gone. That
// would lose the context across `await` of anything already settled, `await 1` included.
class AsyncContextJobQueue final : public JS::JobQueue {
  using ObjectVector = JS::GCVector<JSObject *, 0, js::SystemAllocPolicy>;

  JS::PersistentRooted<ObjectVector> jobs_;
  JS::PersistentRooted<ObjectVector> contexts_;
  size_t next_ = 0;
  bool draining_ = false;

  class SavedQueue final : public JS::JobQueue::SavedJobQueue {
    AsyncContextJobQueue *queue_;
    JS::PersistentRooted<ObjectVector> jobs_;
    JS::PersistentRooted<ObjectVector> contexts_;
    size_t next_;
    bool draining_;

  public:
    SavedQueue(JSContext *cx, AsyncContextJobQueue *queue)
        : queue_(queue), jobs_(cx), contexts_(cx), next_(queue->next_),
          draining_(queue->draining_) {
      std::swap(jobs_.get(), queue->jobs_.get());
      std::swap(contexts_.get(), queue->contexts_.get());
      queue->next_ = 0;
      queue->draining_ = false;
    }

    ~SavedQueue() override {
      MOZ_ASSERT(queue_->empty());
      std::swap(jobs_.get(), queue_->jobs_.get());
      std::swap(contexts_.get(), queue_->contexts_.get());
      queue_->next_ = next_;
      queue_->draining_ = draining_;
    }
  };

public:
  explicit AsyncContextJobQueue(JSContext *cx) : jobs_(cx), contexts_(cx) {}

  bool getHostDefinedData(JSContext *cx, JS::MutableHandleObject data) const override {
    data.set(CURRENT);
    return true;
  }

  bool getHostDefinedGlobal(JSContext *cx, JS::MutableHandleObject data) const override {
    return true;
  }

  bool enqueuePromiseJob(JSContext *cx, JS::HandleObject promise, JS::HandleObject job,
                         JS::HandleObject allocationSite,
                         JS::HandleObject hostDefinedData) override {
    MOZ_ASSERT(job);
    JSObject *context = is_frame(hostDefinedData) ? hostDefinedData.get() : CURRENT.get();
    if (!jobs_.append(job.get()) || !contexts_.append(context)) {
      JS_ReportOutOfMemory(cx);
      return false;
    }
    JS::JobQueueMayNotBeEmpty(cx);
    return true;
  }

  void runJobs(JSContext *cx) override {
    if (draining_) {
      return;
    }
    draining_ = true;

    JS::RootedObject job(cx);
    JS::RootedObject context(cx);
    JS::RootedValue rval(cx);
    while (next_ < jobs_.length()) {
      job = jobs_[next_].get();
      context = contexts_[next_].get();
      jobs_[next_].set(nullptr);
      contexts_[next_].set(nullptr);
      next_++;

      // If this is the last job, SpiderMonkey may skip enqueuing what it queues next.
      if (next_ == jobs_.length()) {
        JS::JobQueueIsEmpty(cx);
      }

      api::AsyncContext::AutoEnter enter(cx, context);
      JSAutoRealm ar(cx, job);
      if (!JS::Call(cx, JS::UndefinedHandleValue, job, JS::HandleValueArray::empty(), &rval)) {
        // Nothing to report for an uncatchable error.
        if (!JS_IsExceptionPending(cx)) {
          continue;
        }
        JS::RootedValue exception(cx);
        bool got = JS_GetPendingException(cx, &exception);
        JS_ClearPendingException(cx);
        if (got) {
          api::Engine::report_exception(exception, "running a promise job");
        }
      }
    }

    jobs_.clear();
    contexts_.clear();
    next_ = 0;
    draining_ = false;
  }

  bool empty() const override { return next_ >= jobs_.length(); }

  bool isDrainingStopped() const override { return false; }

protected:
  js::UniquePtr<SavedJobQueue> saveJobQueue(JSContext *cx) override {
    auto saved = js::MakeUnique<SavedQueue>(cx, this);
    if (!saved) {
      JS_ReportOutOfMemory(cx);
      return nullptr;
    }
    return saved;
  }
};

AsyncContextJobQueue *JOB_QUEUE = nullptr;

} // namespace

namespace api {

JSObject *AsyncContext::current() { return CURRENT; }

JSObject *AsyncContext::with_value(JSContext *cx, HandleObject parent, HandleObject key,
                                   HandleValue value) {
  MOZ_ASSERT(is_frame(parent));
  MOZ_ASSERT(key);
  return new_frame(cx, parent, key, value, true);
}

JSObject *AsyncContext::without_value(JSContext *cx, HandleObject parent, HandleObject key) {
  MOZ_ASSERT(is_frame(parent));
  MOZ_ASSERT(key);
  return new_frame(cx, parent, key, JS::UndefinedHandleValue, false);
}

bool AsyncContext::lookup(JSObject *context, JSObject *key, JS::MutableHandleValue value) {
  MOZ_ASSERT(is_frame(context));
  for (JSObject *frame = context; frame; frame = frame_object(frame, FrameSlots::Parent)) {
    if (frame_object(frame, FrameSlots::Key) != key) {
      continue;
    }
    if (!JS::GetReservedSlot(frame, std::to_underlying(FrameSlots::Bound)).toBoolean()) {
      return false;
    }
    value.set(JS::GetReservedSlot(frame, std::to_underlying(FrameSlots::Value)));
    return true;
  }
  return false;
}

AsyncContext::AutoEnter::AutoEnter(JSContext *cx, HandleObject context)
    : previous_(cx, CURRENT) {
  MOZ_ASSERT(is_frame(context));
  CURRENT = context.get();
}

AsyncContext::AutoEnter::~AutoEnter() { CURRENT = previous_.get(); }

bool AsyncContext::init(JSContext *cx) {
  MOZ_ASSERT(!JOB_QUEUE);
  // The job queue below needs SpiderMonkey's legacy job path; see AsyncContextJobQueue.
  MOZ_RELEASE_ASSERT(!JS::Prefs::use_js_microtask_queue());

  EMPTY.init(cx, new_frame(cx, nullptr, nullptr, JS::UndefinedHandleValue, false));
  if (!EMPTY) {
    return false;
  }
  CURRENT.init(cx, EMPTY);

  JOB_QUEUE = js_new<AsyncContextJobQueue>(cx);
  if (!JOB_QUEUE) {
    return false;
  }
  JS::SetJobQueue(cx, JOB_QUEUE);
  return true;
}

void AsyncContext::reset() { CURRENT = EMPTY.get(); }

} // namespace api
