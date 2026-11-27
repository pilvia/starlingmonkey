// A response body whose stream errors while it is sent is abandoned, not finished: the client
// sees the response fail instead of taking the part it got for the whole. It fails in the fetch
// or in reading the body, as far as the host had sent it. The stream's error is reported.
addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.pathname === '/inner') {
    let sent = 0;
    event.respondWith(new Response(new ReadableStream({
      pull(controller) {
        if (sent++ < 2) {
          controller.enqueue(new Uint8Array(1000));
        } else {
          controller.error(new Error('boom'));
        }
      },
    }, { highWaterMark: 0 })));
    return;
  }

  event.respondWith((async () => {
    try {
      const response = await fetch(new URL('/inner', url));
      const text = await response.text();
      return new Response(`inner: ${response.status} ${text.length} bytes\n`);
    } catch (e) {
      return new Response(`inner: ${e.name}\n`);
    }
  })());
});
