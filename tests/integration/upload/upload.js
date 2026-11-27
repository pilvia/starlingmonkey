import { serveTest } from '../test-server.js';
import { assert, strictEqual, rejects } from '../../assert.js';

// A request body the peer stops reading must settle the fetch instead of ending the event loop.
// The peer stops on a refused connect, or when it answers early without reading. Port 1 is
// closed on every host the suite runs on, so a connect to it is refused at once.
const CLOSED_PORT = 'http://127.0.0.1:1/';
const BIG = 8 << 20;

// A body that arrives in 64 KiB chunks, one every 5 ms: still producing when the peer goes away.
// `onCancel` receives the reason the stream is cancelled with.
function slowStream(onCancel) {
  let sent = 0;
  return new ReadableStream({
    async pull(controller) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      controller.enqueue(new Uint8Array(64 << 10));
      sent += 64 << 10;
      if (sent >= 4 << 20) {
        controller.close();
      }
    },
    cancel(reason) {
      onCancel?.(reason);
    },
  }, { highWaterMark: 0 });
}

// A body of `count` chunks of ten bytes, with no length of its own: what is sent is whatever
// `content-length` the request declares.
function tenByteChunks(count, onCancel) {
  let sent = 0;
  return new ReadableStream({
    pull(controller) {
      if (sent++ < count) {
        controller.enqueue(new Uint8Array(10).fill(97));
      } else {
        controller.close();
      }
    },
    cancel(reason) {
      onCancel?.(reason);
    },
  }, { highWaterMark: 0 });
}

// A body that sends two chunks of 1000 bytes, and then errors with `error`.
function erroringStream(error) {
  let sent = 0;
  return new ReadableStream({
    pull(controller) {
      if (sent++ < 2) {
        controller.enqueue(new Uint8Array(1000));
      } else {
        controller.error(error);
      }
    },
  }, { highWaterMark: 0 });
}

// A body that yields strings, which a body stream may not.
function stringStream(onCancel) {
  return new ReadableStream({
    pull(controller) {
      controller.enqueue('name=Ada');
    },
    cancel(reason) {
      onCancel?.(reason);
    },
  }, { highWaterMark: 0 });
}

// What an upload to an upstream that answers 413 at once settles to. Either is right: hyper's
// client reports an answer that arrives while the body is still being sent as an error, even
// when the server reads the rest.
async function statusOrTypeError(promise) {
  try {
    return (await promise).status;
  } catch (e) {
    assert(e instanceof TypeError, `expected a TypeError, got ${e}`);
    return 'TypeError';
  }
}

export const handler = (evt) => serveTest(async (t) => {
  const early413 = new URL('/early413', evt.request.url).href;
  const bodyLength = new URL('/bodyLength', evt.request.url).href;

  await t.test('big-body-to-a-closed-port', async () => {
    await rejects(() => fetch(CLOSED_PORT, { method: 'POST', body: new Uint8Array(BIG) }),
                  TypeError);
  });

  await t.test('slow-stream-to-a-closed-port', async () => {
    let reason;
    await rejects(() => fetch(CLOSED_PORT, {
      method: 'POST',
      body: slowStream((r) => { reason = r; }),
      duplex: 'half',
    }), TypeError);
    assert(reason instanceof TypeError, `the body stream is cancelled with a TypeError, not ${reason}`);
  });

  await t.test('small-body-to-a-closed-port', async () => {
    await rejects(() => fetch(CLOSED_PORT, { method: 'POST', body: 'name=Ada' }), TypeError);
  });

  await t.test('small-body-to-an-early-413', async () => {
    const response = await fetch(early413, { method: 'POST', body: 'name=Ada' });
    strictEqual(response.status, 413);
  });

  await t.test('big-body-to-an-early-413', async () => {
    const outcome = await statusOrTypeError(
      fetch(early413, { method: 'POST', body: new Uint8Array(BIG) }));
    assert(outcome === 413 || outcome === 'TypeError', `settled as ${outcome}`);
  });

  await t.test('slow-stream-to-an-early-413', async () => {
    const outcome = await statusOrTypeError(
      fetch(early413, { method: 'POST', body: slowStream(), duplex: 'half' }));
    assert(outcome === 413 || outcome === 'TypeError', `settled as ${outcome}`);
  });

  // The host refuses the write that goes past the declared length, and sends only what fits. The
  // peer got a body cut short, so the fetch rejects rather than settle with the peer's answer.
  await t.test('stream-longer-than-its-content-length', async () => {
    let reason;
    await rejects(() => fetch(bodyLength, {
      method: 'POST',
      headers: { 'content-length': '15' },
      body: tenByteChunks(4, (r) => { reason = r; }),
      duplex: 'half',
    }), TypeError);
    assert(reason instanceof TypeError, `the body stream is cancelled with a TypeError, not ${reason}`);
  });

  // A body whose stream errors while it is sent: the fetch rejects with a TypeError whose cause
  // is the stream's error, and the request goes on.
  await t.test('stream-that-errors-while-sent', async () => {
    const boom = new Error('boom');
    let error;
    try {
      await fetch(bodyLength, { method: 'POST', body: erroringStream(boom), duplex: 'half' });
    } catch (e) {
      error = e;
    }
    assert(error instanceof TypeError, `the fetch rejects with a TypeError, not ${error}`);
    strictEqual(error.cause, boom, "the TypeError's cause is the stream's error");
  });

  await t.test('stream-of-strings', async () => {
    let reason;
    await rejects(() => fetch(bodyLength, {
      method: 'POST',
      body: stringStream((r) => { reason = r; }),
      duplex: 'half',
    }), TypeError);
    assert(reason instanceof TypeError, `the body stream is cancelled with a TypeError, not ${reason}`);
  });

  // A body whose length is known sets the request's Content-Length, whatever the caller's headers
  // say: here they are stale, as when a proxy forwards the headers of a body it rewrote.
  await t.test('known-length-body-with-a-stale-content-length', async () => {
    for (const declared of ['3', '64']) {
      const response = await fetch(bodyLength, {
        method: 'POST',
        headers: { 'content-length': declared },
        body: 'name=Ada',
      });
      strictEqual(await response.text(), 'length 8', `with content-length: ${declared}`);
    }
  });

  await t.test('stream-as-long-as-its-content-length', async () => {
    const response = await fetch(bodyLength, {
      method: 'POST',
      headers: { 'content-length': '20' },
      body: tenByteChunks(2),
      duplex: 'half',
    });
    strictEqual(await response.text(), 'length 20');
  });
})(evt);

// The upstream of the 413 cases: it answers without reading the body.
export function early413() {
  return new Response('payload too large', { status: 413 });
}

// The upstream of the content-length cases: it answers with the length of the body it read.
export async function bodyLength(evt) {
  return new Response(`length ${(await evt.request.arrayBuffer()).byteLength}`);
}
