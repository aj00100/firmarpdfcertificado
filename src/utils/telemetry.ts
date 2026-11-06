// src/utils/telemetry.ts
export type TelemetryEvent =
  | 'tool_view'
  | 'pdf_loaded'
  | 'p12_loaded'
  | 'p12_help_expanded'
  | 'p12_help_tab_switched'
  | 'sign_attempt'
  | 'sign_success'
  | 'sign_error'
  | 'validator_pdf_loaded'
  | 'validator_success';

export interface TelemetryProps {
  [key: string]: string | number | boolean | undefined;
}

export function trackEvent(event: TelemetryEvent, props: TelemetryProps = {}): void {
  try {
    if (typeof window === 'undefined') return;

    // 1. Safe GA4 Dispatch (when not blocked by ad-blocker or cookie consent)
    const win = window as any;
    if (typeof win.gtag === 'function') {
      win.gtag('event', event, props);
    }

    // 2. Zero-Cookie First-Party Beacon (Immune to ad-blockers & Safari ITP)
    const payload = JSON.stringify({
      event,
      props,
      timestamp: Date.now(),
      path: window.location.pathname,
    });

    if (navigator.sendBeacon) {
      navigator.sendBeacon('/api/event', payload);
    } else {
      fetch('/api/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        keepalive: true,
      }).catch(() => {
        // Fail silently; zero impact on client UX
      });
    }
  } catch (_) {
    // Fail silently; never interrupt user interaction
  }
}
