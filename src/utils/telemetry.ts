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

export function trackEvent(_event: TelemetryEvent, _props: TelemetryProps = {}): void {
  // Cookieless, zero third-party tracking. Completely local to fulfill LSSI/AEPD strict privacy.
  return;
}
