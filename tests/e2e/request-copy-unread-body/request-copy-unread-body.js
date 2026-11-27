// Copying the incoming request reads its body through the copy, whether or not the original's
// `body` getter ran first. The copy has no host body of its own to append the incoming one to.
addEventListener('fetch', (event) => {
  event.respondWith(handle(event.request));
});

async function handle(request) {
  const url = new URL(request.url);
  if (url.pathname === '/copy') {
    if (request.headers.get('x-mode') === 'getter') {
      request.body;
    }
    const copy = new Request(request);
    return new Response(`${copy.method} ${await copy.text()}\n`);
  }

  let out = '';
  for (const mode of ['direct', 'getter']) {
    const response = await fetch(new URL('/copy', url), {
      method: 'POST',
      headers: { 'x-mode': mode },
      body: 'name=Ada',
    });
    out += `${mode}: ${response.status} ${await response.text()}`;
  }
  return new Response(out);
}
