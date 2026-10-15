// "How to fix" guides for the Website Security Check, keyed by check id (and by data.code where the
// fix differs). Pure data plus a lookup: guideFor(checkId, code) and renderMessage(guide, values).
// The guides are attached server-side to warn/fail checks (lib/website-scan.js), so the browser gets
// them in the report JSON and there is no second copy to keep in sync.
//
// Every step and snippet was checked against the official page listed in the guide's `sources`
// (read from the vendors' own documentation repositories: cloudflare/cloudflare-docs, mdn/content,
// nginx/nginx.org, apache/httpd docs/manual, MicrosoftDocs/iis-docs, WordPress/wordpress-develop,
// php/doc-en). Where a vendor page couldn't be confirmed the step says "check with your host"
// instead of guessing.

/* ------------------------------------------------------------------ */
/* Sources                                                             */
/* ------------------------------------------------------------------ */

const S = {
  cfAlwaysHttps: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/",
  cfHsts: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/",
  cfMinTls: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/",
  cfRewrites: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/",
  cfRespHeaders: "https://developers.cloudflare.com/rules/transform/response-header-modification/",
  cfRespHeadersDash: "https://developers.cloudflare.com/rules/transform/response-header-modification/create-dashboard/",
  cfTransformPlans: "https://developers.cloudflare.com/rules/transform/",
  apHeaders: "https://httpd.apache.org/docs/2.4/mod/mod_headers.html",
  apRewrite: "https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html",
  apForceHttps: "https://httpd.apache.org/docs/2.4/rewrite/remapping.html",
  apServerTokens: "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens",
  apServerSignature: "https://httpd.apache.org/docs/2.4/mod/core.html#serversignature",
  ngHeaders: "https://nginx.org/en/docs/http/ngx_http_headers_module.html",
  ngReturn: "https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return",
  ngServerTokens: "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",
  ngCookieFlags: "https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_flags",
  iisHeaders: "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpprotocol/customheaders/",
  iisHsts: "https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10-version-1709/iis-10-version-1709-hsts",
  iisRewrite: "https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/using-the-url-rewrite-module",
  iisRequestFiltering: "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/",
  wpHttps: "https://developer.wordpress.org/advanced-administration/security/https/",
  wpUpdating: "https://wordpress.org/documentation/article/updating-wordpress/",
  wpAutoUpdates: "https://wordpress.org/documentation/article/configuring-automatic-background-updates/",
  phpSession: "https://www.php.net/manual/en/session.configuration.php",
  mdnHsts: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security",
  mdnCsp: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy",
  mdnCspReportOnly: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy-Report-Only",
  mdnXfo: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options",
  mdnNosniff: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options",
  mdnReferrer: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy",
  mdnPermissions: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy",
  mdnSetCookie: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie",
  mdnAcac: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Credentials",
  mdnSri: "https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity",
  mdnMixed: "https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content",
  shopifySsl: "https://help.shopify.com/en/manual/domains/ssl",
  wixHeaders: "https://support.wix.com/en/article/request-adding-and-customizing-security-headers",
};

/* ------------------------------------------------------------------ */
/* Shared platform text                                                */
/* ------------------------------------------------------------------ */

// Cloudflare: Response Header Transform Rules (dashboard steps from create-dashboard.mdx; plan limits
// from rules/transform/index.mdx: Free 10, Pro 25, Business 50 active Transform Rules).
const cfHeaderSteps = (name, value) => [
  "In the Cloudflare dashboard, go to the Rules Overview page.",
  "Select Create rule > Response Header Transform Rule and give it a name (e.g. \"Security headers\").",
  "Under \"When incoming requests match\", choose All incoming requests.",
  `Under Modify response header, choose Set static, Header name: ${name}, Value: ${value}.`,
  "Select Deploy. One rule can set up to 30 headers, so put all your security headers in the same rule.",
];
const CF_PLAN_NOTE = "Works only if the domain is proxied through Cloudflare (orange cloud). Free plans allow 10 active Transform Rules, so keep all security headers in one rule.";

// Builders: managed hosting with limited control over headers. Wix: custom headers only on Wix Studio
// for enterprise (support.wix.com). Shopify: free automatic TLS (help.shopify.com/en/manual/domains/ssl).
// Squarespace / GoDaddy Website Builder: no official page confirmed, so "ask support".
const builders = (what, { possible = false, extra = [] } = {}) => ({
  id: "builders",
  label: "Wix / Squarespace / GoDaddy / Shopify",
  possible,
  steps: [
    ...extra,
    `Website builders manage the server for you and usually handle HTTPS and the certificate automatically. Most do not let you add your own response headers, so ${what} may not be possible on the builder itself.`,
    "Wix: custom security headers are only available on Wix Studio for enterprise. Shopify and Squarespace control the storefront's headers. GoDaddy Website Builder: ask GoDaddy support.",
    "Send the message below to the builder's support team and ask whether they can do it for you.",
    "Putting the domain behind free Cloudflare can add headers, but many builders block or complicate proxying. Check with the builder first.",
  ],
  note: "Not something the site owner can usually change. Ask the builder's support.",
});

const builderManagedTls = {
  id: "builders",
  label: "Wix / Squarespace / GoDaddy / Shopify",
  possible: "partial",
  steps: [
    "Builders issue and renew the certificate for you. Shopify, for example, provides free certificates for every connected domain, which can take up to 48 hours to appear.",
    "Check the domain settings in the builder: the domain must point at the builder exactly as its instructions say (A/CNAME records), or the certificate can't be issued.",
    "If the builder shows the certificate as pending or failed for more than two days, contact its support with the message below.",
  ],
};

const RUN_AGAIN = "Run the Website Security Check again.";

/* ------------------------------------------------------------------ */
/* Guides                                                              */
/* ------------------------------------------------------------------ */

export const FIX_GUIDES = {
  /* ---------------- HTTPS ---------------- */
  https: {
    why: "Without HTTPS, anything a visitor types into the site (contact forms, logins, payment details) travels unencrypted and can be read or changed on public Wi-Fi. Browsers also label the site \"Not secure\".",
    difficulty: "moderate",
    time: "30–60 minutes",
    platforms: [
      {
        id: "cloudflare",
        label: "Cloudflare",
        possible: true,
        steps: [
          "Make sure the domain's DNS records are proxied (orange cloud) and the SSL/TLS encryption mode is not Off.",
          "Cloudflare issues a free edge certificate automatically once the domain is active.",
          "Go to the Edge Certificates page and turn on Always Use HTTPS.",
        ],
        note: "Full (strict) encryption mode also needs a certificate on the web server itself; ask the host for a free one.",
      },
      {
        id: "wordpress",
        label: "WordPress",
        possible: true,
        steps: [
          "Turn on the free SSL certificate in the hosting control panel (most hosts offer one-click Let's Encrypt).",
          "In WordPress go to Settings → General and change both WordPress Address (URL) and Site Address (URL) to start with https://. You'll be logged out; log back in at the https:// address.",
          "If those fields are greyed out, they're set in wp-config.php (WP_HOME / WP_SITEURL); ask your developer to change them there.",
        ],
      },
      {
        id: "apache",
        label: "Apache",
        possible: true,
        steps: [
          "Install a certificate (most hosts offer free Let's Encrypt in the control panel; on your own server use certbot).",
          "Add a redirect from HTTP to HTTPS (see the HTTP → HTTPS redirect guide).",
        ],
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: true,
        steps: [
          "Install a certificate (free Let's Encrypt via the host's panel or certbot) and add a listen 443 ssl; server block that uses it.",
          "Add a redirect from HTTP to HTTPS (see the HTTP → HTTPS redirect guide).",
        ],
      },
      {
        id: "iis",
        label: "IIS (Windows)",
        possible: true,
        steps: [
          "In IIS Manager, add an https binding (port 443) to the site and select a certificate. Free certificates are available through ACME clients such as win-acme.",
          "Then add the HTTP → HTTPS redirect (see that guide).",
        ],
      },
      { ...builderManagedTls, possible: true },
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nDetails: {detail}\n\nCould you please turn on HTTPS for the site with a free, auto-renewing certificate (e.g. Let's Encrypt) and make sure every page loads over https://?\n\nOnce it's done, https://{domain} should load without any browser warning. Thank you!",
    verify: "Open https://{domain} in a browser: the address bar should show a padlock with no warning. Then run the check again.",
    sources: [S.cfAlwaysHttps, S.wpHttps, S.apForceHttps, S.iisHsts, S.shopifySsl],
    variants: {
      downgrade: {
        why: "The secure address sends visitors back to an unencrypted http:// page, so the protection HTTPS gives is lost.",
        difficulty: "easy",
        time: "10–20 minutes",
        message:
          "Hi,\n\nOur IT provider checked {domain} and found that the secure address redirects back to plain http://.\n\nDetails: {detail}\n\nCould you please remove the redirect from https:// to http:// (often an old rule in .htaccess, the server config or a plugin) and serve the whole site over HTTPS?\n\nAfterwards https://{domain} should stay on https://. Thank you!",
      },
    },
  },

  /* ---------------- HTTP → HTTPS redirect ---------------- */
  "https-redirect": {
    why: "If someone types the address without https://, the site still loads unencrypted. A redirect sends every visitor to the secure version automatically.",
    difficulty: "easy",
    time: "10–20 minutes",
    platforms: [
      {
        id: "cloudflare",
        label: "Cloudflare",
        possible: true,
        steps: [
          "Go to the SSL/TLS Overview page and make sure the encryption mode is not Off (otherwise the option is hidden).",
          "Go to the Edge Certificates page and turn on Always Use HTTPS.",
        ],
        note: "Cloudflare recommends doing the redirect at Cloudflare rather than also on the web server, to avoid redirect loops.",
      },
      {
        id: "wordpress",
        label: "WordPress",
        possible: true,
        steps: [
          "First make sure Settings → General uses https:// for both WordPress Address (URL) and Site Address (URL).",
          "Then add the redirect in the hosting panel (many hosts have a \"Force HTTPS\" switch) or in the .htaccess file shown in the Apache tab. Most WordPress hosts run Apache or LiteSpeed, which read .htaccess.",
        ],
      },
      {
        id: "apache",
        label: "Apache",
        possible: true,
        steps: [
          "Best: in the server config, give the port-80 virtual host a Redirect permanent \"/\" \"https://{domain}/\".",
          "Without server access, add these lines to the top of the site's .htaccess file:",
        ],
        // httpd.apache.org/docs/2.4/rewrite/remapping.html ("Forcing HTTPS", .htaccess variant).
        // %{REQUEST_URI} is used instead of the recipe's $1 because in .htaccess the leading
        // slash is stripped from the matched path (mod_rewrite.html, RewriteRule per-directory notes).
        snippet: {
          lang: "apache",
          code: "<IfModule mod_rewrite.c>\n  RewriteEngine On\n  RewriteCond \"%{HTTPS}\" !=on\n  RewriteRule \"^\" \"https://%{SERVER_NAME}%{REQUEST_URI}\" [R=301,L]\n</IfModule>",
        },
        note: "Behind a load balancer or Cloudflare, %{HTTPS} is always off and this causes a redirect loop. Use the hosting panel or Cloudflare's Always Use HTTPS instead.",
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: true,
        steps: ["Replace the port-80 server block's contents with a single redirect:"],
        // nginx.org/en/docs/http/ngx_http_rewrite_module.html#return
        snippet: { lang: "nginx", code: "server {\n    listen 80;\n    server_name {domain} www.{domain};\n    return 301 https://$host$request_uri;\n}" },
      },
      {
        id: "iis",
        label: "IIS (Windows)",
        possible: true,
        steps: [
          "IIS 10 version 1709 or newer: on the site's <hsts> settings set redirectHttpToHttps=\"true\" (IIS Manager → site → HSTS, or the configuration editor).",
          "Older IIS: install the free URL Rewrite module from Microsoft and add this rule to the site's web.config:",
        ],
        // learn.microsoft.com .../iis-10-version-1709-hsts (sample-urlrewrite-single-site.xml)
        snippet: {
          lang: "xml",
          code: "<configuration>\n  <system.webServer>\n    <rewrite>\n      <rules>\n        <rule name=\"Redirect HTTP to HTTPS\" stopProcessing=\"true\">\n          <match url=\"(.*)\" />\n          <conditions>\n            <add input=\"{HTTPS}\" pattern=\"off\" />\n          </conditions>\n          <action type=\"Redirect\" url=\"https://{HTTP_HOST}/{R:1}\" redirectType=\"Permanent\" />\n        </rule>\n      </rules>\n    </rewrite>\n  </system.webServer>\n</configuration>",
        },
      },
      {
        ...builderManagedTls,
        steps: [
          "Builders normally redirect to HTTPS automatically once the certificate is active. Check the builder's SSL/HTTPS setting is turned on (on Squarespace, the SSL panel under Settings).",
          "If plain http:// still loads, ask the builder's support with the message below.",
        ],
      },
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found that the site still loads over plain http:// without redirecting to https://.\n\nDetails: {detail}\n\nCould you please add a permanent (301) redirect from http:// to https:// for the whole site?\n\nAfterwards, opening http://{domain} should land on https://{domain}. Thank you!",
    verify: "Type http://{domain} (with http://) into a browser: it should switch to https:// by itself. Then run the check again.",
    sources: [S.cfAlwaysHttps, S.apForceHttps, S.apRewrite, S.ngReturn, S.iisHsts, S.iisRewrite, S.wpHttps],
  },

  /* ---------------- Certificate ---------------- */
  ssl: {
    why: "A broken or expired certificate makes browsers show a full-page security warning, and most visitors leave.",
    difficulty: "easy",
    time: "15–30 minutes",
    risk: "Changing certificates or TLS settings can take the site offline if something is misconfigured. Make the change at a quiet time, and test the site in a browser straight afterwards.",
    platforms: [
      {
        id: "cloudflare",
        label: "Cloudflare",
        possible: true,
        steps: [
          "Visitors see Cloudflare's edge certificate, which Cloudflare renews automatically. Check the Edge Certificates page shows an active certificate covering both {domain} and www.{domain}.",
          "If the site uses Full (strict) mode, the web server's own certificate must also be valid. Ask the host to renew it.",
        ],
      },
      {
        id: "wordpress",
        label: "WordPress",
        possible: true,
        steps: [
          "Certificates are handled by the host, not WordPress. In the hosting control panel open the SSL/TLS (or \"Let's Encrypt\") section and reissue the certificate for {domain} and www.{domain}, with auto-renew on.",
        ],
      },
      { id: "apache", label: "Apache", possible: true, steps: ["Renew or reissue the certificate (e.g. certbot renew, or the host's panel) so it covers both {domain} and www.{domain}, then reload Apache.", "Make sure automatic renewal is scheduled."] },
      { id: "nginx", label: "Nginx", possible: true, steps: ["Renew or reissue the certificate (e.g. certbot renew, or the host's panel) so it covers both {domain} and www.{domain}, then reload nginx.", "Make sure automatic renewal is scheduled."] },
      { id: "iis", label: "IIS (Windows)", possible: true, steps: ["In IIS Manager → Server Certificates, renew or import a certificate that covers {domain} and www.{domain}, then select it on the site's https binding.", "Use an ACME client (e.g. win-acme) for free automatic renewal."] },
      builderManagedTls,
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found a problem with the website's security certificate: {finding}\n\nDetails: {detail}\n\nCould you please renew or reissue the certificate so it covers both {domain} and www.{domain}, and confirm it renews automatically?\n\nAfterwards both addresses should open without a browser warning. Thank you!",
    verify: "Open https://{domain} and https://www.{domain}: both should show a padlock. Click the padlock → certificate details to see the new expiry date.",
    sources: [S.cfMinTls, S.shopifySsl],
    variants: {
      expiring: { why: "The certificate expires soon. If it doesn't renew on time, visitors get a full-page security warning.", time: "5–15 minutes" },
      "expiring-urgent": { why: "The certificate expires within a week. After that, visitors get a full-page security warning until it's renewed.", time: "5–15 minutes" },
      "www-invalid": {
        why: "The main address is fine, but anyone who types www. in front gets a security warning.",
        message:
          "Hi,\n\nOur IT provider checked {domain} and found that the certificate doesn't cover www.{domain}.\n\nDetails: {detail}\n\nCould you please add www.{domain} to the certificate (or redirect www.{domain} to {domain} with a valid certificate)?\n\nAfterwards https://www.{domain} should open without a warning. Thank you!",
      },
    },
  },

  /* ---------------- TLS version / key ---------------- */
  "tls-details": {
    why: "The server only offers old encryption (TLS 1.0/1.1) or a weak key. Modern browsers refuse or warn about these connections.",
    difficulty: "advanced",
    time: "30–60 minutes",
    risk: "Test before turning off old protocols: very old devices or connected systems (payment terminals, scanners) may stop connecting. Change it at a quiet time and check the site and anything that connects to it straight afterwards.",
    platforms: [
      {
        id: "cloudflare",
        label: "Cloudflare",
        possible: true,
        steps: ["Go to the Edge Certificates page and set Minimum TLS Version to TLS 1.2."],
        note: "Applies to the whole zone. Not available for Cloudflare Pages hostnames.",
      },
      { id: "wordpress", label: "WordPress", possible: false, steps: ["This is a server setting, not a WordPress one. Ask the host to enable TLS 1.2 and 1.3 (or use the Cloudflare option)."] },
      {
        id: "apache",
        label: "Apache",
        possible: "partial",
        steps: ["In the server's SSL config (not .htaccess), allow only TLS 1.2 and newer, then reload Apache. On shared hosting ask the host.", "Verify with your host: the exact directive (SSLProtocol) and file depend on the server."],
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: "partial",
        steps: ["In the server block's TLS settings allow only TLS 1.2 and 1.3, then reload nginx. On shared hosting ask the host.", "Verify with your host: the exact directive (ssl_protocols) and file depend on the server."],
      },
      { id: "iis", label: "IIS (Windows)", possible: "partial", steps: ["TLS versions are set for the whole Windows server, not per site. Ask whoever manages the server to disable TLS 1.0/1.1 and enable TLS 1.2/1.3, and test after a reboot."] },
      { ...builderManagedTls, steps: ["Builders manage TLS for you; if this shows up on a builder site, contact the builder's support with the message below."] },
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nDetails: {detail}\n\nCould you please enable TLS 1.2 and TLS 1.3 (and disable TLS 1.0/1.1), and make sure the certificate uses at least a 2048-bit RSA or an EC key?\n\nAfterwards the site should still load normally in current browsers. Thank you!",
    verify: RUN_AGAIN + " The TLS row should show TLSv1.2 or TLSv1.3.",
    sources: [S.cfMinTls],
    variants: {
      "weak-key": {
        why: "The certificate uses a short RSA key that can be broken with enough computing power.",
        difficulty: "moderate",
        time: "15–30 minutes",
        message:
          "Hi,\n\nOur IT provider checked {domain} and found that the certificate uses a weak key.\n\nDetails: {detail}\n\nCould you please reissue the certificate with a 2048-bit (or larger) RSA key, or an EC key?\n\nThank you!",
      },
    },
  },

  /* ---------------- HSTS ---------------- */
  hsts: {
    why: "HSTS tells browsers to always use the secure version of the site, even if someone types http:// or follows an old link. It stops a first visit on public Wi-Fi from being downgraded.",
    difficulty: "easy",
    time: "10–15 minutes, then a few weeks of gradual increases",
    risk:
      "Once a browser has seen HSTS, it refuses to load the site without HTTPS until max-age runs out. Start small: max-age=300 (5 minutes), then 604800 (1 week), then 15552000–31536000 (6–12 months) once everything works. Only add includeSubDomains if EVERY subdomain (mail., shop., old test sites) works over HTTPS, or they become unreachable. Don't add preload: getting a site off the browser preload list takes months, so it isn't recommended for small offices.",
    platforms: [
      {
        id: "cloudflare",
        label: "Cloudflare",
        possible: true,
        steps: [
          "Go to the Edge Certificates page. Under HTTP Strict Transport Security (HSTS), select Enable HSTS, read the dialog and select I understand, then Next.",
          "Set Max Age Header to the smallest option (1 month) at first. Leave Apply HSTS policy to subdomains and Preload off. Select Save.",
          "Cloudflare's shortest option is 1 month. To start at 5 minutes instead, use a Response Header Transform Rule with Set static, Header name: Strict-Transport-Security, Value: max-age=300.",
        ],
        note: "Before turning HSTS off later, set Max Age Header to 0 (Disable) and wait for the old max-age to run out, or visitors may be locked out.",
      },
      {
        id: "wordpress",
        label: "WordPress",
        possible: true,
        steps: [
          "Many hosts have a \"HSTS\" or \"Security headers\" switch in the control panel; use it if available.",
          "Otherwise add the Apache lines below to the site's .htaccess (most WordPress hosts run Apache or LiteSpeed). Ask the host if you're unsure.",
        ],
      },
      {
        id: "apache",
        label: "Apache",
        possible: true,
        steps: ["Add to .htaccess (or the HTTPS virtual host). Start with 300, then raise max-age step by step:"],
        // httpd.apache.org/docs/2.4/mod/mod_headers.html (Header always set)
        snippet: { lang: "apache", code: "<IfModule mod_headers.c>\n  Header always set Strict-Transport-Security \"max-age=300\"\n</IfModule>" },
        note: "Final value once everything works: \"max-age=31536000\".",
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: true,
        steps: [
          "Add to the HTTPS server { } block. Start with 300, then raise max-age step by step:",
          "Note: an add_header inside a location { } block REPLACES all add_header lines inherited from the server block. Repeat the security headers in that location, or keep them only in server.",
        ],
        // nginx.org/en/docs/http/ngx_http_headers_module.html (add_header ... always; inheritance rule)
        snippet: { lang: "nginx", code: "add_header Strict-Transport-Security \"max-age=300\" always;" },
      },
      {
        id: "iis",
        label: "IIS (Windows)",
        possible: true,
        steps: [
          "IIS 10 version 1709 or newer: in the site's <hsts> settings set enabled=\"true\" and max-age=\"300\" (raise it later).",
          "Older IIS: add the header in web.config:",
        ],
        // learn.microsoft.com .../httpprotocol/customheaders/
        snippet: {
          lang: "xml",
          code: "<configuration>\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n        <add name=\"Strict-Transport-Security\" value=\"max-age=300\" />\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>",
        },
        note: "Older IIS sends custom headers on http:// too; browsers ignore HSTS there, which is harmless.",
      },
      builders("HSTS", { possible: "partial", extra: ["Squarespace has an HSTS option in its SSL settings when the Secure setting is on (verify with Squarespace support)."] }),
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nDetails: {detail}\n\nCould you please add the Strict-Transport-Security header to the site's HTTPS responses? Please start with max-age=300, and once we've confirmed nothing breaks, raise it to max-age=31536000. Please don't add includeSubDomains or preload for now.\n\nYou can confirm it in the browser's developer tools under Network → response headers. Thank you!",
    verify: "In the browser's developer tools (F12) → Network → reload → click the page → Response Headers: look for Strict-Transport-Security. Or run the check again.",
    sources: [S.mdnHsts, S.cfHsts, S.cfRespHeadersDash, S.apHeaders, S.ngHeaders, S.iisHsts, S.iisHeaders],
    variants: {
      "no-https": { why: "HSTS only works once the site runs on HTTPS. Fix HTTPS first (see that guide), then come back to this." },
      "http-only": { why: "The header is only sent on the unencrypted http:// page, where browsers ignore it. It has to be sent on the https:// page." },
      disabled: { why: "The header is there but switched off (max-age=0 or missing), so browsers aren't protected." },
      short: { why: "HSTS is on but only for a short time, so returning visitors lose the protection quickly. Six to twelve months is recommended once everything works." },
    },
  },

  /* ---------------- Clickjacking ---------------- */
  clickjacking: {
    why: "Without this header, another website can load this site inside an invisible frame and trick visitors into clicking buttons on it.",
    difficulty: "easy",
    time: "5–15 minutes",
    risk: "This can break legitimate embeds, such as a booking or contact widget from this site shown on another website. DENY also blocks some admin tools (e.g. the WordPress Customizer preview). Use SAMEORIGIN, which still allows the site to frame itself.",
    platforms: [
      { id: "cloudflare", label: "Cloudflare", possible: true, steps: cfHeaderSteps("X-Frame-Options", "SAMEORIGIN"), note: CF_PLAN_NOTE },
      { id: "wordpress", label: "WordPress", possible: true, steps: ["Use the host's \"security headers\" option if there is one; otherwise add the Apache lines to .htaccess.", "Check the Customizer (Appearance → Customize) still loads afterwards."] },
      {
        id: "apache",
        label: "Apache",
        possible: true,
        steps: ["Add to .htaccess or the virtual host:"],
        // httpd.apache.org/docs/2.4/mod/mod_headers.html
        snippet: { lang: "apache", code: "<IfModule mod_headers.c>\n  Header always set X-Frame-Options \"SAMEORIGIN\"\n</IfModule>" },
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: true,
        steps: ["Add to the server { } block (not a location block, which would replace inherited headers):"],
        // nginx.org/en/docs/http/ngx_http_headers_module.html
        snippet: { lang: "nginx", code: "add_header X-Frame-Options \"SAMEORIGIN\" always;" },
      },
      {
        id: "iis",
        label: "IIS (Windows)",
        possible: true,
        steps: ["Add to web.config:"],
        // learn.microsoft.com .../httpprotocol/customheaders/
        snippet: { lang: "xml", code: "<configuration>\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n        <add name=\"X-Frame-Options\" value=\"SAMEORIGIN\" />\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>" },
      },
      builders("clickjacking protection"),
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nDetails: {detail}\n\nCould you please add the response header X-Frame-Options: SAMEORIGIN (or a Content-Security-Policy frame-ancestors 'self' directive)? Please check that any widgets we embed on other sites still work afterwards.\n\nThank you!",
    verify: "Developer tools (F12) → Network → reload → Response Headers: look for X-Frame-Options: SAMEORIGIN. Or run the check again.",
    sources: [S.mdnXfo, S.cfRespHeadersDash, S.cfTransformPlans, S.apHeaders, S.ngHeaders, S.iisHeaders],
    variants: {
      weak: { why: "A framing rule is set, but with a value browsers ignore (ALLOW-FROM is obsolete), so there's no protection." },
    },
  },

  /* ---------------- nosniff ---------------- */
  nosniff: {
    why: "Without this header, browsers may guess a file's type, which can let an uploaded file be run as a script.",
    difficulty: "easy",
    time: "5–10 minutes",
    platforms: [
      {
        id: "cloudflare",
        label: "Cloudflare",
        possible: true,
        steps: ["Quickest: on the Edge Certificates page, the HSTS settings include a No-Sniff Header switch.", "Or use a Response Header Transform Rule:", ...cfHeaderSteps("X-Content-Type-Options", "nosniff")],
        note: CF_PLAN_NOTE,
      },
      { id: "wordpress", label: "WordPress", possible: true, steps: ["Use the host's \"security headers\" option if there is one; otherwise add the Apache lines to .htaccess."] },
      {
        id: "apache",
        label: "Apache",
        possible: true,
        steps: ["Add to .htaccess or the virtual host:"],
        // httpd.apache.org/docs/2.4/mod/mod_headers.html
        snippet: { lang: "apache", code: "<IfModule mod_headers.c>\n  Header always set X-Content-Type-Options \"nosniff\"\n</IfModule>" },
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: true,
        steps: ["Add to the server { } block:"],
        // nginx.org/en/docs/http/ngx_http_headers_module.html
        snippet: { lang: "nginx", code: "add_header X-Content-Type-Options \"nosniff\" always;" },
      },
      {
        id: "iis",
        label: "IIS (Windows)",
        possible: true,
        steps: ["Add to web.config:"],
        // learn.microsoft.com .../httpprotocol/customheaders/
        snippet: { lang: "xml", code: "<configuration>\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n        <add name=\"X-Content-Type-Options\" value=\"nosniff\" />\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>" },
      },
      builders("this header"),
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found that the X-Content-Type-Options header is missing.\n\nDetails: {detail}\n\nCould you please add the response header X-Content-Type-Options: nosniff to the site?\n\nThank you!",
    verify: "Developer tools (F12) → Network → reload → Response Headers: look for X-Content-Type-Options: nosniff. Or run the check again.",
    sources: [S.mdnNosniff, S.cfHsts, S.cfRespHeadersDash, S.apHeaders, S.ngHeaders, S.iisHeaders],
  },

  /* ---------------- CSP ---------------- */
  csp: {
    why: "A Content-Security-Policy lists where the site's scripts may come from. If a plugin or third-party script is ever hacked, it limits what the attacker's code can do.",
    difficulty: "advanced",
    time: "1–3 hours, then a week of monitoring",
    risk:
      "A wrong policy can break the site (menus, forms, analytics, payment widgets). Always start with Content-Security-Policy-Report-Only, which only reports problems, and check the browser console on the main pages for a week before switching the header name to Content-Security-Policy. WordPress page builders and many plugins need 'unsafe-inline'; that's acceptable as a first step.",
    platforms: [
      {
        id: "cloudflare",
        label: "Cloudflare",
        possible: true,
        steps: [...cfHeaderSteps("Content-Security-Policy-Report-Only", "default-src 'self' https: data: 'unsafe-inline'; object-src 'none'; base-uri 'self'"), "Watch the browser console for a week, list the sites scripts really come from, tighten the policy, then rename the header to Content-Security-Policy."],
        note: CF_PLAN_NOTE,
      },
      {
        id: "wordpress",
        label: "WordPress",
        possible: "partial",
        steps: ["Add the Report-Only header via the host's panel or .htaccess (Apache tab).", "Click through the site and the admin with the browser console open (F12 → Console) and note what's reported.", "Page builders and plugins often need 'unsafe-inline' and several outside domains; keep the policy loose at first."],
      },
      {
        id: "apache",
        label: "Apache",
        possible: true,
        steps: ["Start in report-only mode (.htaccess or virtual host):", "After a week without unexpected reports, tighten the sources and change the header name to Content-Security-Policy."],
        // httpd.apache.org/docs/2.4/mod/mod_headers.html; MDN Content-Security-Policy-Report-Only
        snippet: { lang: "apache", code: "<IfModule mod_headers.c>\n  Header always set Content-Security-Policy-Report-Only \"default-src 'self' https: data: 'unsafe-inline'; object-src 'none'; base-uri 'self'\"\n</IfModule>" },
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: true,
        steps: ["Start in report-only mode (server { } block):", "After a week without unexpected reports, tighten the sources and change the header name to Content-Security-Policy."],
        // nginx.org/en/docs/http/ngx_http_headers_module.html; MDN Content-Security-Policy-Report-Only
        snippet: { lang: "nginx", code: "add_header Content-Security-Policy-Report-Only \"default-src 'self' https: data: 'unsafe-inline'; object-src 'none'; base-uri 'self'\" always;" },
      },
      {
        id: "iis",
        label: "IIS (Windows)",
        possible: true,
        steps: ["Start in report-only mode (web.config):", "After a week without unexpected reports, tighten the sources and change the header name to Content-Security-Policy."],
        // learn.microsoft.com .../httpprotocol/customheaders/
        snippet: { lang: "xml", code: "<configuration>\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n        <add name=\"Content-Security-Policy-Report-Only\" value=\"default-src 'self' https: data: 'unsafe-inline'; object-src 'none'; base-uri 'self'\" />\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>" },
      },
      builders("a Content-Security-Policy"),
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nDetails: {detail}\n\nCould you please add a Content-Security-Policy, starting in Content-Security-Policy-Report-Only mode so nothing breaks? Once a week of browser-console reports looks clean, please switch it to an enforced Content-Security-Policy that limits where scripts can load from.\n\nThank you!",
    verify: "Developer tools (F12) → Network → Response Headers shows the policy, and the Console lists anything it would block. Run the check again after switching to the enforced header.",
    sources: [S.mdnCsp, S.mdnCspReportOnly, S.cfRespHeadersDash, S.cfTransformPlans, S.apHeaders, S.ngHeaders, S.iisHeaders],
    variants: {
      "report-only": { why: "The policy is only reporting, so it doesn't block anything yet. If the reports have been clean for a while, it's time to enforce it.", difficulty: "moderate", time: "15–30 minutes" },
      weak: { why: "A policy is set, but it still lets scripts run from anywhere (or allows inline scripts without a nonce/hash), so it gives little protection.", difficulty: "advanced" },
      "no-script-policy": { why: "A policy is set, but it doesn't say where scripts may come from (no script-src or default-src), so it doesn't limit injected code." },
    },
  },

  /* ---------------- Referrer-Policy ---------------- */
  "referrer-policy": {
    why: "The current setting sends the full address of each page (which can include private details in the URL) to every other website a visitor clicks through to.",
    difficulty: "easy",
    time: "5–10 minutes",
    platforms: [
      { id: "cloudflare", label: "Cloudflare", possible: true, steps: cfHeaderSteps("Referrer-Policy", "strict-origin-when-cross-origin"), note: CF_PLAN_NOTE },
      { id: "wordpress", label: "WordPress", possible: true, steps: ["Look for a plugin or host setting that sets Referrer-Policy to unsafe-url and change it, or set the header in .htaccess (Apache tab)."] },
      {
        id: "apache",
        label: "Apache",
        possible: true,
        steps: ["Replace the current value (.htaccess or virtual host):"],
        // httpd.apache.org/docs/2.4/mod/mod_headers.html
        snippet: { lang: "apache", code: "<IfModule mod_headers.c>\n  Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n</IfModule>" },
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: true,
        steps: ["Replace the current add_header line in the server { } block:"],
        // nginx.org/en/docs/http/ngx_http_headers_module.html
        snippet: { lang: "nginx", code: "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;" },
      },
      {
        id: "iis",
        label: "IIS (Windows)",
        possible: true,
        steps: ["Replace the current value in web.config:"],
        // learn.microsoft.com .../httpprotocol/customheaders/
        snippet: { lang: "xml", code: "<configuration>\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n        <remove name=\"Referrer-Policy\" />\n        <add name=\"Referrer-Policy\" value=\"strict-origin-when-cross-origin\" />\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>" },
      },
      builders("changing this header"),
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found that the Referrer-Policy sends full page addresses to other websites.\n\nDetails: {detail}\n\nCould you please set Referrer-Policy to strict-origin-when-cross-origin (or remove the header so the browser default applies)?\n\nThank you!",
    verify: "Developer tools (F12) → Network → Response Headers: Referrer-Policy should be strict-origin-when-cross-origin, or absent. Or run the check again.",
    sources: [S.mdnReferrer, S.cfRespHeadersDash, S.apHeaders, S.ngHeaders, S.iisHeaders],
  },

  /* ---------------- Permissions-Policy (info only, optional) ---------------- */
  "permissions-policy": {
    why: "Optional. It stops embedded scripts from asking for the camera, microphone or location. It isn't scored.",
    difficulty: "easy",
    time: "5–10 minutes",
    platforms: [
      { id: "cloudflare", label: "Cloudflare", possible: true, steps: cfHeaderSteps("Permissions-Policy", "camera=(), microphone=(), geolocation=()"), note: CF_PLAN_NOTE },
      { id: "wordpress", label: "WordPress", possible: true, steps: ["Optional: add the Apache lines to .htaccess, or use the host's security headers option."] },
      { id: "apache", label: "Apache", possible: true, steps: ["Optional (.htaccess or virtual host):"], snippet: { lang: "apache", code: "<IfModule mod_headers.c>\n  Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n</IfModule>" } },
      { id: "nginx", label: "Nginx", possible: true, steps: ["Optional (server { } block):"], snippet: { lang: "nginx", code: "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;" } },
      { id: "iis", label: "IIS (Windows)", possible: true, steps: ["Optional (web.config):"], snippet: { lang: "xml", code: "<configuration>\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n        <add name=\"Permissions-Policy\" value=\"camera=(), microphone=(), geolocation=()\" />\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>" } },
      builders("this optional header"),
    ],
    message: "Hi,\n\nOptional improvement for {domain}: {finding}\n\nIf it's easy, could you add Permissions-Policy: camera=(), microphone=(), geolocation=() (allowing anything the site actually uses)?\n\nThank you!",
    verify: "Developer tools (F12) → Network → Response Headers: look for Permissions-Policy.",
    sources: [S.mdnPermissions, S.cfRespHeadersDash, S.apHeaders, S.ngHeaders, S.iisHeaders],
  },

  /* ---------------- CORS ---------------- */
  cors: {
    why: "The site lets another website read its pages using the visitor's login cookies. If the server copies whatever origin it's sent, any website could read a logged-in visitor's data.",
    difficulty: "advanced",
    time: "30–60 minutes",
    platforms: [
      { id: "cloudflare", label: "Cloudflare", possible: "partial", steps: ["CORS headers usually come from the application. If a Transform Rule adds Access-Control-Allow-Credentials, remove it or limit it to your own origins.", "Otherwise send the message below to the developer."] },
      { id: "wordpress", label: "WordPress", possible: "partial", steps: ["Usually set by a plugin (APIs, headless or membership plugins) or custom code. Find the plugin that adds Access-Control-Allow-Credentials and limit it to your own domains."] },
      { id: "apache", label: "Apache", possible: "partial", steps: ["Look for Header set Access-Control-Allow-Origin / Access-Control-Allow-Credentials lines in .htaccess or the config. Allow credentials only for a fixed list of your own origins, never an echoed Origin or \"null\"."] },
      { id: "nginx", label: "Nginx", possible: "partial", steps: ["Look for add_header Access-Control-Allow-Origin $http_origin style lines. Allow credentials only for a fixed list of your own origins, never an echoed Origin or \"null\"."] },
      { id: "iis", label: "IIS (Windows)", possible: "partial", steps: ["Check web.config customHeaders and the application's CORS settings. Allow credentials only for a fixed list of your own origins."] },
      builders("changing CORS"),
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found that the site allows cross-origin requests with credentials.\n\nDetails: {detail}\n\nCould you please make sure Access-Control-Allow-Credentials is only sent for a fixed list of our own origins, and that the server never echoes back an arbitrary Origin (or \"null\")?\n\nThank you!",
    verify: RUN_AGAIN,
    sources: [S.mdnAcac],
  },

  /* ---------------- Cookies ---------------- */
  cookies: {
    why: "Cookies without the Secure flag can be sent over an unencrypted connection, where someone on the same Wi-Fi can copy them and take over a logged-in session.",
    difficulty: "moderate",
    time: "15–30 minutes",
    risk: "Changing flags on login or session cookies can log everyone out once. A wrong SameSite value can break payment or single sign-on returns. Change one thing at a time, then test logging in, the checkout and any \"sign in with…\" buttons.",
    platforms: [
      { id: "cloudflare", label: "Cloudflare", possible: false, steps: ["Cookie flags are set by the website software, so fix them there (see the other tabs). Cloudflare's Always Use HTTPS helps, but doesn't add the Secure flag."] },
      {
        id: "wordpress",
        label: "WordPress",
        possible: true,
        steps: [
          "WordPress marks its login cookie Secure only when Settings → General → Site Address (URL) starts with https://. Make sure both URLs there use https://.",
          "Other cookies come from plugins (shop, forms, membership). Update them, and check their settings for a \"secure cookies\" option.",
          "PHP session cookies (PHPSESSID): set the PHP options in the next tab via the host's PHP settings.",
        ],
      },
      {
        id: "apache",
        label: "Apache",
        possible: "partial",
        steps: ["Cookies come from the application. For PHP sessions, set these in php.ini or the host's PHP settings panel:", "For other software, ask the developer to set the Secure and HttpOnly attributes when the cookie is created."],
        // php.net/manual/en/session.configuration.php
        snippet: { lang: "ini", code: "session.cookie_secure = 1\nsession.cookie_httponly = 1" },
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: "partial",
        steps: ["Best fixed in the application (see the Apache tab for PHP). If nginx proxies to the application, nginx 1.19.3+ can add flags in the location that proxies:"],
        // nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_flags
        snippet: { lang: "nginx", code: "proxy_cookie_flags ~ secure httponly;" },
        note: "This adds HttpOnly to every proxied cookie. If a script on the page needs to read a cookie, name the cookies individually instead of ~.",
      },
      { id: "iis", label: "IIS (Windows)", possible: "partial", steps: ["Cookies come from the application (ASP.NET, PHP). Ask the developer to require SSL and HttpOnly for the session and login cookies. Verify with your developer: the exact setting depends on the framework."] },
      builders("changing cookie flags", { extra: ["Cookies on builder sites are set by the builder and its apps. If an added app sets the cookie, ask that app's support."] }),
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nCookies: {detail}\n\nCould you please make sure all cookies are set with the Secure attribute, and that login/session cookies also have HttpOnly? Please test logging in and the checkout afterwards.\n\nThank you!",
    verify: "Developer tools (F12) → Application (or Storage) → Cookies: the Secure and HttpOnly columns should be ticked. Or run the check again.",
    sources: [S.mdnSetCookie, S.wpHttps, S.phpSession, S.ngCookieFlags],
    variants: {
      "httponly-missing": {
        why: "A login or session cookie can be read by scripts on the page, so a single malicious script could steal it and take over the session.",
        message:
          "Hi,\n\nOur IT provider checked {domain} and found a session cookie without the HttpOnly flag.\n\nCookies: {detail}\n\nCould you please set HttpOnly (and Secure) on login/session cookies? Please test logging in afterwards.\n\nThank you!",
      },
    },
  },

  /* ---------------- Mixed content ---------------- */
  "mixed-content": {
    why: "The secure page loads scripts, styles or forms over unencrypted http://. Browsers block these (which can break the page), and on an untrusted network they could be swapped for something malicious.",
    difficulty: "moderate",
    time: "15–60 minutes",
    platforms: [
      { id: "cloudflare", label: "Cloudflare", possible: "partial", steps: ["Go to the Edge Certificates page and turn on Automatic HTTPS Rewrites. Cloudflare rewrites http:// links to https:// where the resource is available over HTTPS.", "It can't fix links added by JavaScript or resources that don't support HTTPS; change those in the site itself."] },
      {
        id: "wordpress",
        label: "WordPress",
        possible: true,
        steps: [
          "Make sure Settings → General uses https:// for both addresses.",
          "Old http:// links usually sit in posts and theme settings in the database. Optional: the free Better Search Replace plugin can replace http://{domain} with https://{domain}. Take a backup first and do a dry run.",
          "For links in the theme or a page builder, edit them there.",
        ],
      },
      { id: "apache", label: "Apache", possible: true, steps: ["Change the http:// links listed in the details to https:// (or relative paths) in the site's HTML, templates or CMS."] },
      { id: "nginx", label: "Nginx", possible: true, steps: ["Change the http:// links listed in the details to https:// (or relative paths) in the site's HTML, templates or CMS."] },
      { id: "iis", label: "IIS (Windows)", possible: true, steps: ["Change the http:// links listed in the details to https:// (or relative paths) in the site's HTML, templates or CMS."] },
      { id: "builders", label: "Wix / Squarespace / GoDaddy / Shopify", possible: true, steps: ["Look for embedded code blocks, custom HTML widgets or theme code that use http:// links, and change them to https://.", "Shopify's SSL help pages cover fixing mixed content; for other builders, ask support."] },
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found insecure http:// content on the secure homepage.\n\nDetails: {detail}\n\nCould you please change these links to https:// (or relative paths)?\n\nAfterwards, the browser's developer tools console shouldn't show any mixed content warnings. Thank you!",
    verify: "Open the homepage, press F12 → Console: there should be no \"Mixed Content\" messages. Then run the check again.",
    sources: [S.mdnMixed, S.cfRewrites, S.wpHttps],
    variants: {
      passive: { why: "The secure page loads some images or media over http://. Browsers upgrade or flag these, and the page may show as not fully secure.", difficulty: "easy", time: "15–30 minutes" },
    },
  },

  /* ---------------- SRI ---------------- */
  sri: {
    why: "The site runs scripts from smaller third-party sites without an integrity check. If one of those sites is hacked, the attacker's code runs on this site too.",
    difficulty: "moderate",
    time: "30–60 minutes",
    platforms: [
      { id: "cloudflare", label: "Cloudflare", possible: false, steps: ["Integrity attributes are part of the page's HTML, so they're added in the website itself (see the other tabs)."] },
      { id: "wordpress", label: "WordPress", possible: "partial", steps: ["Most third-party scripts are added by a plugin or theme. Check whether the plugin can load the script from your own site instead, or ask the plugin author to support integrity attributes."] },
      {
        id: "apache",
        label: "Apache",
        possible: true,
        steps: ["Best: copy fixed-version library files onto your own site and load them from there.", "Otherwise add integrity and crossorigin attributes to the script tag (the library's CDN usually publishes the hash):"],
        // developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity
        snippet: { lang: "html", code: "<script src=\"https://cdn.example.com/library-1.2.3.min.js\"\n        integrity=\"sha384-REPLACE_WITH_PUBLISHED_HASH\"\n        crossorigin=\"anonymous\"></script>" },
      },
      { id: "nginx", label: "Nginx", possible: true, steps: ["Same as Apache: host the file yourself, or add integrity= and crossorigin=\"anonymous\" to the script tag in the site's HTML."] },
      { id: "iis", label: "IIS (Windows)", possible: true, steps: ["Same as Apache: host the file yourself, or add integrity= and crossorigin=\"anonymous\" to the script tag in the site's HTML."] },
      { id: "builders", label: "Wix / Squarespace / GoDaddy / Shopify", possible: "partial", steps: ["If you pasted the script into a custom code block, add the integrity and crossorigin attributes there. Scripts added by the builder's own apps can't be changed; ask the app's support."] },
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found third-party scripts loaded without an integrity check.\n\nDetails: {detail}\n\nCould you please host those scripts on our own site, or add integrity= and crossorigin=\"anonymous\" attributes for fixed library versions?\n\nThank you!",
    verify: RUN_AGAIN + " The browser console will show an error if an integrity hash doesn't match.",
    sources: [S.mdnSri],
  },

  /* ---------------- Version disclosure ---------------- */
  "version-disclosure": {
    why: "The server announces the exact software versions it runs, which makes it quick for attackers to look up known weaknesses. Hiding them doesn't fix anything by itself; keeping the software updated does.",
    difficulty: "moderate",
    time: "10–20 minutes",
    platforms: [
      { id: "cloudflare", label: "Cloudflare", possible: "partial", steps: ["Cloudflare can't change the Server header. A Response Header Transform Rule with Remove can drop X-Powered-By (Header name: X-Powered-By).", "For the Server header, fix it on the web server (other tabs)."] },
      { id: "wordpress", label: "WordPress", possible: "partial", steps: ["These headers come from the web server and PHP, not WordPress. Ask the host to hide them (ServerTokens Prod, expose_php = Off), or use the Apache tab if you manage the server."] },
      {
        id: "apache",
        label: "Apache",
        possible: "partial",
        steps: [
          "ServerTokens can only be set in the main server config (not .htaccess). On shared hosting, ask the host.",
          "ServerSignature can go in .htaccess.",
          "In PHP's settings set expose_php = Off to remove X-Powered-By.",
        ],
        // httpd.apache.org/docs/2.4/mod/core.html#servertokens and #serversignature (contexts)
        snippet: { lang: "apache", code: "# Main server config only (httpd.conf / apache2.conf):\nServerTokens Prod\nServerSignature Off" },
      },
      {
        id: "nginx",
        label: "Nginx",
        possible: true,
        steps: ["Add to the http { } (or server { }) block, then reload nginx:", "For PHP, also set expose_php = Off in php.ini."],
        // nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens
        snippet: { lang: "nginx", code: "server_tokens off;" },
      },
      {
        id: "iis",
        label: "IIS (Windows)",
        possible: true,
        steps: ["IIS 10+: request filtering can remove the Server header, and customHeaders can remove X-Powered-By (web.config):"],
        // learn.microsoft.com .../requestfiltering/ (removeServerHeader, IIS 10+); .../customheaders/ (remove)
        snippet: { lang: "xml", code: "<configuration>\n  <system.webServer>\n    <security>\n      <requestFiltering removeServerHeader=\"true\" />\n    </security>\n    <httpProtocol>\n      <customHeaders>\n        <remove name=\"X-Powered-By\" />\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>" },
      },
      builders("hiding these headers"),
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found that the server shows exact software versions.\n\nDetails: {detail}\n\nCould you please hide the version numbers (e.g. ServerTokens Prod / server_tokens off, and expose_php = Off), and confirm the server software is up to date?\n\nThank you!",
    verify: "Developer tools (F12) → Network → Response Headers: Server and X-Powered-By should no longer show version numbers. Or run the check again.",
    sources: [S.apServerTokens, S.apServerSignature, S.ngServerTokens, S.iisRequestFiltering, S.iisHeaders, S.cfRespHeaders],
  },

  /* ---------------- WordPress ---------------- */
  "cms-wordpress": {
    why: "Out-of-date WordPress is the most common way small-business websites get hacked. Updates fix security holes that are already public.",
    difficulty: "easy",
    time: "15–45 minutes",
    risk: "Take a full backup (files and database) first. Update plugins and themes too, not just WordPress itself. Check the site afterwards, especially forms, the shop and page-builder pages.",
    platforms: [
      { id: "cloudflare", label: "Cloudflare", possible: false, steps: ["Updates happen inside WordPress (see the WordPress tab). If Cloudflare caches pages, purge the cache afterwards."] },
      {
        id: "wordpress",
        label: "WordPress",
        possible: true,
        steps: [
          "Back up the site (host backup or a backup plugin) and confirm it finished.",
          "Go to Dashboard → Updates and update WordPress, then plugins, then themes.",
          "Turn on automatic updates: on Dashboard → Updates enable automatic updates for all new versions, and on the Plugins page select Enable auto-updates for trusted plugins.",
          "Or have the developer add define( 'WP_AUTO_UPDATE_CORE', 'minor' ); (security releases only) or true (all releases) to wp-config.php.",
        ],
        // WordPress core: wp-admin/includes/class-core-upgrader.php (WP_AUTO_UPDATE_CORE: true | 'minor' | false)
        snippet: { lang: "php", code: "// wp-config.php, above \"That's all, stop editing!\"\ndefine( 'WP_AUTO_UPDATE_CORE', 'minor' );" },
      },
      { id: "apache", label: "Apache", possible: "partial", steps: ["Updates are done in WordPress itself (see the WordPress tab). Also keep PHP on a supported version in the host's panel."] },
      { id: "nginx", label: "Nginx", possible: "partial", steps: ["Updates are done in WordPress itself (see the WordPress tab). Also keep PHP on a supported version."] },
      { id: "iis", label: "IIS (Windows)", possible: "partial", steps: ["Updates are done in WordPress itself (see the WordPress tab). Also keep PHP on a supported version."] },
      { id: "builders", label: "Wix / Squarespace / GoDaddy / Shopify", possible: false, steps: ["Not applicable: builder platforms update their own software. This guide only applies to WordPress sites."] },
    ],
    message:
      "Hi,\n\nOur IT provider checked {domain} and found that WordPress is out of date.\n\nDetails: {detail}\n\nCould you please take a full backup, then update WordPress, all plugins and the theme, and turn on automatic security updates?\n\nThank you!",
    verify: "Dashboard → Updates should say everything is up to date. Then run the check again.",
    sources: [S.wpUpdating, S.wpAutoUpdates],
    variants: {
      "branches-behind": { why: "This WordPress version is two or more major releases behind and may no longer get security fixes. Out-of-date WordPress is the most common way small-business websites get hacked.", time: "30–90 minutes", difficulty: "moderate" },
    },
  },
};

/* ------------------------------------------------------------------ */
/* Lookup                                                              */
/* ------------------------------------------------------------------ */

/**
 * The guide for a check, with the data.code variant (when there is one) laid over the default.
 * Returns null for checks without a guide. The `variants` table itself is not included.
 */
export function guideFor(checkId, code) {
  const base = FIX_GUIDES[checkId];
  if (!base) return null;
  const { variants, ...rest } = base;
  const variant = (code && variants && variants[code]) || null;
  return { checkId, code: variant ? code : null, ...rest, ...(variant || {}) };
}

/** Fill {domain}, {finding} and {detail} in a guide's text fields. Values are inserted once, never re-scanned. */
export function fillPlaceholders(text, values) {
  return String(text).replace(/\{(domain|finding|detail)\}/g, (_, k) => String(values[k] ?? ""));
}

/** A guide ready to show for one check: placeholders filled in the message, verify text and steps. */
export function renderGuide(check, domain) {
  const g = guideFor(check.id, check.data?.code);
  if (!g) return null;
  const values = { domain, finding: check.summary || check.title, detail: String(check.detail || "").slice(0, 600) };
  const fill = (t) => fillPlaceholders(t, values);
  return {
    ...g,
    message: fill(g.message),
    verify: fill(g.verify),
    platforms: g.platforms.map((p) => ({
      ...p,
      steps: p.steps.map((s) => fillPlaceholders(s, { domain, finding: "", detail: "" })),
      ...(p.snippet ? { snippet: { ...p.snippet, code: p.snippet.code.replace(/\{domain\}/g, domain) } } : {}),
    })),
  };
}
