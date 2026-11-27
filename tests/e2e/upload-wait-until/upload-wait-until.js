// An upload the peer stops reading fails its fetch and nothing else: work the request still has
// to do after the response has started, here in `waitUntil`, goes on. The response body stays
// open until that work is done, so the test sees it end.
addEventListener('fetch', (event) => {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  event.respondWith(new Response(readable));
  event.waitUntil((async () => {
    try {
      await fetch('http://127.0.0.1:1/', { method: 'POST', body: new Uint8Array(8 << 20) });
      await writer.write(encoder.encode('upload: resolved\n'));
    } catch (e) {
      await writer.write(encoder.encode(`upload: ${e.name}\n`));
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
    await writer.write(encoder.encode('waitUntil: done\n'));
    await writer.close();
  })());
});
