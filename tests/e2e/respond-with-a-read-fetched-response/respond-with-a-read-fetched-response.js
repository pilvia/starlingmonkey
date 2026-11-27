// A Response that came from a fetch can be the fetch event's response after its body was
// touched: its `body` getter ran, or it was cloned and the clone read. Its body is then sent
// from its stream, chunk by chunk, to the event's own response body. The Response itself still
// holds the incoming body it came from, which is not a body to write to.
addEventListener('fetch', (event) => {
  event.respondWith(handle(event.request));
});

async function handle(request) {
  const url = new URL(request.url);
  if (url.pathname === '/upstream') {
    return new Response('x'.repeat(100000));
  }
  if (url.pathname === '/forward') {
    const response = await fetch(new URL('/upstream', url));
    const mode = url.searchParams.get('mode');
    if (mode === 'body') {
      response.body;
    } else if (mode === 'clone') {
      await response.clone().text();
    }
    return response;
  }

  let out = '';
  for (const mode of ['body', 'clone']) {
    try {
      const response = await fetch(new URL(`/forward?mode=${mode}`, url));
      out += `${mode}: ${response.status} ${(await response.text()).length}\n`;
    } catch (e) {
      out += `${mode}: ${e.name}\n`;
    }
  }
  return new Response(out);
}
