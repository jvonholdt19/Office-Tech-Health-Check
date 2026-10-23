// Consent to check a domain: every scan form has the box "I own this domain or have the owner's
// permission to check it." (public/legal.js), and the APIs refuse a scan without it.
// GET requests carry ?consent=true; JSON POSTs carry { consent: true }. Nothing else is recorded:
// the existing audit event just notes consent: true.

export const CONSENT_REQUIRED = "Please confirm you own this domain or have the owner's permission to check it.";

/** True only for an explicit consent=true (query) or consent: true (JSON body). */
export function consentGiven(url, body) {
  if (body && typeof body === "object" && body.consent === true) return true;
  return url?.searchParams?.get("consent") === "true";
}
