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
  | 'sign_err_wrong_pass'
  | 'sign_err_p12_format'
  | 'sign_err_pdf_encrypted'
  | 'sign_err_cert_expired'
  | 'sign_err_cert_not_yet_valid'
  | 'sign_err_no_private_key'
  | 'sign_err_worker_crash'
  | 'sign_err_unknown'
  | 'validator_pdf_loaded'
  | 'validator_success'
  | 'validator_error'
  | 'cert_check_loaded'
  | 'cert_check_attempt'
  | 'cert_check_success'
  | 'cert_check_error'
  | 'cert_err_wrong_pass'
  | 'cert_err_format'
  | 'affiliate_click';

export interface TelemetryProps {
  [key: string]: string | number | boolean | undefined;
}

export function trackEvent(event: TelemetryEvent, props: TelemetryProps = {}): void {
  try {
    if (typeof window === 'undefined') return;

    // Strict privacy hygiene: filter out any inadvertent user/file metadata
    const sanitizedProps: TelemetryProps = {};
    const forbiddenKeys = ['filename', 'file_name', 'name', 'nif', 'cn', 'subject', 'issuer', 'stack', 'pass', 'password'];
    for (const [key, val] of Object.entries(props)) {
      if (forbiddenKeys.includes(key.toLowerCase())) continue;
      sanitizedProps[key] = val;
    }

    const win = window as any;
    if (typeof win.gtag === 'function') {
      win.gtag('event', event, sanitizedProps);
    }
  } catch (_) {
    // Fail silently; never interrupt user interaction
  }
}
