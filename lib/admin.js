// Admin access. Today every signed-in technician is an admin (Josh is both), so isAdmin() is true
// for any valid session. To add a separate admin role later, decide it here (e.g. from a role in
// the session or an allowlist) and every admin page and API that uses isAdmin/authorizeAdmin follows.
import { authorize, send } from "./private-api.js";

/** True when this signed-in session may see admin pages (pricing sheet). */
export function isAdmin(session) {
  return Boolean(session && session.sid);
}

/** authorize() plus the admin check: 403 for a signed-in technician who isn't an admin. */
export async function authorizeAdmin(req, res) {
  const ctx = await authorize(req, res);
  if (!ctx) return null;
  if (!isAdmin(ctx)) {
    send(res, 403, { error: "This page is for admins only." });
    return null;
  }
  return ctx;
}
