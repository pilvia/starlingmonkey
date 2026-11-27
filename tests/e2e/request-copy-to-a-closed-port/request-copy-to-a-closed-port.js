// A copy of the incoming request, forwarded to a peer that refuses the connection, settles its
// fetch. The copy's body is read from the incoming one a chunk at a time, and a read can still
// be pending when the peer goes away and the body is cancelled: that read finds nobody left to
// deliver to, and stops there instead of ending the event loop. The read is pending when the
// incoming body arrives after its headers, so the body here is sent 300 ms late, and with a
// declared length, which makes its end readable together with its last byte.
addEventListener('fetch', (event) => {
  event.respondWith(handle(event.request));
});

async function handle(request) {
  const url = new URL(request.url);
  if (url.pathname === '/forward') {
    try {
      await fetch(new Request('http://127.0.0.1:1/', new Request(request)));
      return new Response('resolved\n');
    } catch (e) {
      return new Response(`${e.name}\n`);
    }
  }

  const lateBody = new ReadableStream({
    async start(controller) {
      await new Promise((resolve) => setTimeout(resolve, 300));
      controller.enqueue(new TextEncoder().encode('x'.repeat(5000)));
      controller.close();
    },
  });
  const response = await fetch(new URL('/forward', url), {
    method: 'POST',
    headers: { 'content-length': '5000' },
    body: lateBody,
    duplex: 'half',
  });
  return new Response(`forward: ${response.status} ${await response.text()}`);
}
