// Feature switches, read from the environment on every request (no redeploy-time baking).
// A tool behind a switch is built and deployed but stays off until its variable is exactly "true".

/** Breach Check (/tools/breach, /api/breach). Off unless BREACH_CHECK_ENABLED is exactly "true". */
export function breachCheckEnabled(env = process.env) {
  return env.BREACH_CHECK_ENABLED === "true";
}

/** The switches a signed-in technician's pages need, as booleans only (sent with GET/POST /api/session). */
export function features(env = process.env) {
  return { breachCheck: breachCheckEnabled(env) };
}
