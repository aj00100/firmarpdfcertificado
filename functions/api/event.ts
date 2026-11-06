// functions/api/event.ts - Cloudflare Pages Event Beacon Handler
export async function onRequestPost(context: { request: Request }) {
  try {
    const data = await context.request.json();
    // Log to Cloudflare Pages real-time dashboard logs (Zero PII, $0 cost)
    console.log(JSON.stringify({
      telemetry: 'firmarpdf_event',
      event: (data as any)?.event,
      props: (data as any)?.props,
      path: (data as any)?.path,
      ts: (data as any)?.timestamp,
    }));
  } catch (_) {
    // Fail silently on malformed payload
  }

  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
    },
  });
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
