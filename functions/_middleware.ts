// functions/_middleware.ts - Cloudflare Pages Edge Canonical Redirect Middleware
export async function onRequest(context: { request: Request; next: () => Promise<Response> }) {
  const url = new URL(context.request.url);

  // Intercept staging domains and www, returning an edge-level HTTP 301 Permanent Redirect
  if (
    url.hostname.endsWith('.pages.dev') ||
    url.hostname.endsWith('.workers.dev') ||
    url.hostname === 'www.firmarpdfcertificado.com'
  ) {
    const destination = `https://firmarpdfcertificado.com${url.pathname}${url.search}`;
    return Response.redirect(destination, 301);
  }

  return await context.next();
}
