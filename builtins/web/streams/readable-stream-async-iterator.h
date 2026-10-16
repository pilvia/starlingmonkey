#ifndef BUILTINS_WEB_STREAMS_READABLE_STREAM_ASYNC_ITERATOR_H
#define BUILTINS_WEB_STREAMS_READABLE_STREAM_ASYNC_ITERATOR_H

#include "builtin.h"

namespace builtins::web::streams {

// Adds `values()` and `[Symbol.asyncIterator]()` to SpiderMonkey's
// ReadableStream.prototype.
class ReadableStreamAsyncIterator {
public:
  static bool install(JSContext *cx, JS::HandleObject global);
};

} // namespace builtins::web::streams

#endif
