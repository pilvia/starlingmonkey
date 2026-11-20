globalThis.GLOBAL = {
  isWindow: function() { return false; },
  isWorker: function() { return true; },
  isShadowRealm: function() { return false; },
};

globalThis.window=self;
globalThis.Window={
  prototype: {}
};

{
  let originalAEL = addEventListener;
  let o_clearTimeout = clearTimeout;
  clearTimeout = function(id) {
    if (id === null) {
      return;
    }
    return o_clearTimeout(id);
  }
  addEventListener = function addEventListener_wpt(type, handler) {
    if (type == "fetch") {
      originalAEL(type, handler);
    } else {
      console.log(`Ignoring handler for event ${type}`);
    }
  }
}

globalThis.SharedArrayBuffer = class SharedArrayBuffer{};
globalThis.MessageChannel = class MessageChannel{};
;
