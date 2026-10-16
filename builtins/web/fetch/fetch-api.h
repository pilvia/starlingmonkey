#ifndef BUILTINS_WEB_FETCH_API_H
#define BUILTINS_WEB_FETCH_API_H

#include "builtin.h"
#include "host_api.h"



namespace builtins::web::fetch {

bool install(api::Engine *engine);

/// Runs the redirect steps of https://fetch.spec.whatwg.org/#http-redirect-fetch for an incoming
/// `response` to `request`. Sets `*followed` when a new request went out in its place, in which
/// case `response` is discarded. Returns false with a pending exception on a network error.
bool maybe_follow_redirect(JSContext *cx, JS::HandleObject request,
                           host_api::HttpIncomingResponse *response, bool *followed);

} // namespace builtins::web::fetch



#endif
