// Step-by-step fix generation: turn check failures into numbered, beginner-friendly checklists
// with exact values, DNS host detection, provider detection, and recheck actions.
// Feature 1: detailed fix instructions per check.

import { GOOGLE_MX } from "./checks/email.js";
import { recommendSpf, recommendDmarc } from "./plan.js";

/* ------------------------------------------------------------------ */
/* DNS Host Detection from NS records                                  */
/* ------------------------------------------------------------------ */

const DNS_HOST_PATTERNS = [
  { key: "cloudflare", name: "Cloudflare", match: /\.ns\.cloudflare\.com$/ },
  { key: "godaddy", name: "GoDaddy", match: /domaincontrol\.com$/ },
  { key: "namecheap", name: "Namecheap", match: /registrar-servers\.com$/ },
  { key: "route53", name: "Amazon Route 53", match: /awsdns-.*\.((com|net|org|co\.uk)|amazon\.com)$/ },
  { key: "google-domains", name: "Google Domains", match: /\.googledomains\.com$/ },
  { key: "microsoft", name: "Microsoft DNS", match: /\.azure-dns\.(com|net|org|info)$/ },
  { key: "hostgator", name: "HostGator", match: /\.hostgator\.com$/ },
  { key: "bluehost", name: "Bluehost", match: /\.bluehost\.com$/ },
  { key: "ionos", name: "IONOS", match: /\.(ionos|1and1)\./ },
  { key: "dreamhost", name: "DreamHost", match: /\.dreamhost\.com$/ },
];

/**
 * Detect DNS host from nameserver names. Returns { key, name } or null.
 */
export function detectDnsHostFromNS(nameservers) {
  if (!Array.isArray(nameservers) || nameservers.length === 0) return null;
  const ns = nameservers.map((n) => String(n).toLowerCase());
  for (const host of DNS_HOST_PATTERNS) {
    if (ns.some((n) => host.match.test(n))) {
      return { key: host.key, name: host.name };
    }
  }
  return { key: "other", name: "Other DNS provider" };
}

/* ------------------------------------------------------------------ */
/* Email Provider Detection from MX/SPF                                */
/* ------------------------------------------------------------------ */

/**
 * Detect email provider from MX records (using the same logic as checkEmailPlatform).
 */
export function detectEmailProvider(mx) {
  if (!Array.isArray(mx) || mx.length === 0) return { key: "unknown", name: "Unknown" };
  const mxHost = (rec) => String(rec.exchange || rec).toLowerCase().replace(/\.$/, "");
  
  for (const rec of mx) {
    const host = mxHost(rec);
    if (GOOGLE_MX.test(host)) return { key: "google", name: "Google Workspace" };
    if (/\.mail\.protection\.outlook\.com$|\.mx\.microsoft$/.test(host)) return { key: "microsoft", name: "Microsoft 365" };
    if (/(^|\.)zoho(mail)?\.(com|eu|in)$/.test(host)) return { key: "zoho", name: "Zoho Mail" };
    if (/(^|\.)secureserver\.net$/.test(host)) return { key: "godaddy", name: "GoDaddy Email" };
  }
  
  return { key: "other", name: "Other email provider" };
}

/* ------------------------------------------------------------------ */
/* DNS Host Instructions (where to click)                              */
/* ------------------------------------------------------------------ */

const DNS_HOST_INSTRUCTIONS = {
  cloudflare: {
    addRecord: "In the Cloudflare dashboard, go to DNS → Records, click Add record, select the record type, fill in Name and Content, then click Save.",
    editRecord: "In the Cloudflare dashboard, go to DNS → Records, find the record, click Edit, update the value, then click Save.",
    deleteRecord: "In the Cloudflare dashboard, go to DNS → Records, find the record, click Edit, then click Delete.",
  },
  godaddy: {
    addRecord: "Sign in to GoDaddy Domain Portfolio, select your domain, go to DNS → DNS Records, click Add New Record, select the type, fill in the fields, then click Save.",
    editRecord: "Sign in to GoDaddy Domain Portfolio, select your domain, go to DNS → DNS Records, find the record, click the pencil icon to edit, update the value, then click Save.",
    deleteRecord: "Sign in to GoDaddy Domain Portfolio, select your domain, go to DNS → DNS Records, find the record, click the trash icon to delete it.",
  },
  namecheap: {
    addRecord: "Go to Namecheap Domain List, click Manage next to the domain, select Advanced DNS, click Add New Record, select the type, fill in the fields, then click the green checkmark.",
    editRecord: "Go to Namecheap Domain List, click Manage next to the domain, select Advanced DNS, find the record, edit the value, then click the green checkmark.",
    deleteRecord: "Go to Namecheap Domain List, click Manage next to the domain, select Advanced DNS, find the record, click the trash icon to delete it.",
  },
  "microsoft": {
    addRecord: "In the Microsoft 365 admin center, go to Settings → Domains, select the domain, click Manage DNS, then Add record.",
    editRecord: "In the Microsoft 365 admin center, go to Settings → Domains, select the domain, click Manage DNS, find the record and edit it.",
    deleteRecord: "In the Microsoft 365 admin center, go to Settings → Domains, select the domain, click Manage DNS, find the record and delete it.",
  },
  other: {
    addRecord: "In your DNS provider's control panel, add a new DNS record with the type, name, and value shown below.",
    editRecord: "In your DNS provider's control panel, find the existing record and update it to the value shown below.",
    deleteRecord: "In your DNS provider's control panel, find the record and delete it.",
  },
};

function getDnsInstructions(dnsHost) {
  const key = dnsHost?.key || "other";
  return DNS_HOST_INSTRUCTIONS[key] || DNS_HOST_INSTRUCTIONS.other;
}

/* ------------------------------------------------------------------ */
/* Email Provider Setup Instructions                                   */
/* ------------------------------------------------------------------ */

const EMAIL_PROVIDER_DKIM_SETUP = {
  google: {
    name: "Google Workspace",
    steps: [
      "Sign in to the Google Admin console at admin.google.com",
      "Go to Apps → Google Workspace → Gmail → Authenticate email",
      "Select your domain, then click Generate New Record",
      "Copy the DNS Host Name (selector) and TXT record value",
      "Add a TXT record at your DNS provider with that name and value",
      "After 24-48 hours, return to the Admin console and click Start Authentication",
    ],
  },
  microsoft: {
    name: "Microsoft 365",
    steps: [
      "Sign in to the Microsoft 365 admin center",
      "Go to Settings → Domains and select your domain",
      "Microsoft automatically publishes DKIM keys once MX records point to Microsoft",
      "To manually enable: go to Exchange admin center → Protection → DKIM",
      "Select your domain and click Enable if not already enabled",
    ],
  },
  other: {
    name: "your email provider",
    steps: [
      "Check your email provider's documentation for DKIM setup instructions",
      "Most providers give you a DKIM TXT record to add to DNS",
      "The record name is usually something like: selector._domainkey.yourdomain.com",
      "Add that TXT record at your DNS provider, then enable DKIM in your email provider's settings",
    ],
  },
};

function getProviderDkimSetup(provider) {
  const key = provider?.key || "other";
  return EMAIL_PROVIDER_DKIM_SETUP[key] || EMAIL_PROVIDER_DKIM_SETUP.other;
}

/* ------------------------------------------------------------------ */
/* Step Generation for Each Check Type                                 */
/* ------------------------------------------------------------------ */

/**
 * Generate step-by-step fix instructions for an SPF check failure.
 */
export function generateSpfSteps(check, domain, scanData) {
  const steps = [];
  const provider = scanData?.provider || { key: "unknown", name: "Unknown" };
  const dnsHost = scanData?.dnsHost || null;
  const existingSpf = check.data?.records || [];
  
  const spfRec = recommendSpf(existingSpf, provider.key);
  if (!spfRec) {
    return {
      summary: "SPF record needs to be set up to authorize your email senders.",
      steps: [
        { num: 1, action: "Identify all services that send email as your domain (email provider, CRM, billing software, newsletter tools, etc.)" },
        { num: 2, action: "Once you have the complete list, create an SPF record that includes all of them" },
        { num: 3, action: "Contact your IT provider for help setting this up correctly" },
      ],
      recordType: "TXT",
      recordName: domain,
      recordValue: null,
    };
  }

  const instructions = getDnsInstructions(dnsHost);
  const hasExisting = existingSpf.length > 0;

  if (hasExisting) {
    steps.push({
      num: 1,
      action: `Update your existing SPF record${existingSpf.length > 1 ? "s (merge into one)" : ""}`,
      detail: `Your DNS shows ${existingSpf.length} SPF record${existingSpf.length > 1 ? "s" : ""}. There should be exactly one.`,
    });
  } else {
    steps.push({
      num: 1,
      action: "Add a new SPF TXT record",
      detail: "Your domain doesn't have an SPF record yet.",
    });
  }

  steps.push({
    num: 2,
    action: `${hasExisting ? "Edit" : "Add"} the TXT record for ${domain}`,
    detail: instructions[hasExisting ? "editRecord" : "addRecord"],
  });

  steps.push({
    num: 3,
    action: "Set the exact value shown below",
    detail: `This authorizes ${provider.name} and keeps your existing senders.`,
    recordType: "TXT",
    recordName: domain,
    recordValue: spfRec.value,
    recordTTL: 3600,
  });

  if (spfRec.warnings && spfRec.warnings.length > 0) {
    steps.push({
      num: 4,
      action: "Review these warnings",
      detail: spfRec.warnings.join(" "),
      warning: true,
    });
  }

  steps.push({
    num: steps.length + 1,
    action: "Wait 5-10 minutes for DNS to propagate",
    detail: "DNS changes usually take effect within minutes, but can take up to 48 hours.",
  });

  steps.push({
    num: steps.length + 1,
    action: "Recheck in the app",
    detail: "Run the Email Security Check again to confirm the SPF record is correct.",
    recheck: true,
  });

  return {
    summary: hasExisting ? "Fix your SPF record by merging duplicates and adding your email provider." : "Add an SPF record to authorize your email senders.",
    steps,
    recordType: "TXT",
    recordName: domain,
    recordValue: spfRec.value,
    changes: spfRec.changes,
  };
}

/**
 * Generate step-by-step fix instructions for DKIM.
 */
export function generateDkimSteps(check, domain, scanData) {
  const provider = scanData?.provider || { key: "unknown", name: "Unknown" };
  const dnsHost = scanData?.dnsHost || null;
  const instructions = getDnsInstructions(dnsHost);
  const dkimSetup = getProviderDkimSetup(provider);

  const steps = [
    {
      num: 1,
      action: `Set up DKIM in ${provider.name}`,
      detail: `DKIM signing keys are published by your email provider (${provider.name}).`,
    },
  ];

  dkimSetup.steps.forEach((step, i) => {
    steps.push({
      num: i + 2,
      action: step,
      detail: i === dkimSetup.steps.length - 1 ? "This publishes your DKIM public key in DNS." : undefined,
    });
  });

  steps.push({
    num: steps.length + 1,
    action: "Wait 24-48 hours for DNS propagation and provider activation",
    detail: "DKIM keys can take up to 2 days to become active.",
  });

  steps.push({
    num: steps.length + 1,
    action: "Recheck in the app",
    detail: "Run the Email Security Check again to confirm DKIM is working.",
    recheck: true,
  });

  return {
    summary: `Set up DKIM email signing with ${provider.name}.`,
    steps,
    providerName: provider.name,
  };
}

/**
 * Generate step-by-step fix instructions for DMARC.
 */
export function generateDmarcSteps(check, domain, scanData, reportAddress) {
  const dnsHost = scanData?.dnsHost || null;
  const instructions = getDnsInstructions(dnsHost);
  const existingDmarc = check.data?.tags || null;
  const hasExisting = !!existingDmarc;
  
  // For staged rollout: start with p=none
  const policy = "none";
  const dmarcRec = recommendDmarc(policy, reportAddress, existingDmarc);
  
  const steps = [];

  if (hasExisting) {
    steps.push({
      num: 1,
      action: "Update your existing DMARC record",
      detail: "Your domain already has a DMARC record. We'll update it to add monitoring.",
    });
  } else {
    steps.push({
      num: 1,
      action: "Add a new DMARC TXT record",
      detail: "DMARC tells email receivers what to do with messages that fail SPF or DKIM checks.",
    });
  }

  steps.push({
    num: 2,
    action: `${hasExisting ? "Edit" : "Add"} the TXT record for _dmarc.${domain}`,
    detail: instructions[hasExisting ? "editRecord" : "addRecord"],
  });

  steps.push({
    num: 3,
    action: "Set the exact value shown below",
    detail: `This starts with p=none (monitor mode) to safely collect reports before enforcement.`,
    recordType: "TXT",
    recordName: `_dmarc.${domain}`,
    recordValue: dmarcRec.value,
    recordTTL: 3600,
  });

  steps.push({
    num: 4,
    action: "Wait 5-10 minutes for DNS to propagate",
    detail: "DMARC changes take effect within minutes.",
  });

  steps.push({
    num: 5,
    action: "Recheck in the app",
    detail: "Run the Email Security Check again to confirm the DMARC record is correct.",
    recheck: true,
  });

  steps.push({
    num: 6,
    action: "Monitor reports for 2-4 weeks before enforcing",
    detail: "We'll track your domain and notify you when it's safe to move to p=quarantine, then p=reject.",
    note: "DMARC enforcement is staged to prevent legitimate email from being blocked. The tracker will guide you through each stage.",
  });

  return {
    summary: hasExisting ? "Update your DMARC record to start monitoring." : "Add a DMARC record to protect against email spoofing.",
    steps,
    recordType: "TXT",
    recordName: `_dmarc.${domain}`,
    recordValue: dmarcRec.value,
    changes: dmarcRec.changes,
    staged: true,
  };
}

/**
 * Generate step-by-step fix instructions for MX records.
 */
export function generateMxSteps(check, domain, scanData) {
  const provider = scanData?.provider || { key: "unknown", name: "Unknown" };
  const dnsHost = scanData?.dnsHost || null;
  const instructions = getDnsInstructions(dnsHost);

  const steps = [
    {
      num: 1,
      action: "Confirm which email service the business uses",
      detail: `Current MX records point to: ${provider.name}`,
    },
    {
      num: 2,
      action: "Get the correct MX records from your email provider",
      detail: provider.key === "google"
        ? "Google Workspace: smtp.google.com with priority 1"
        : provider.key === "microsoft"
          ? "Microsoft 365: <domain-key>.mail.protection.outlook.com (get exact value from Microsoft 365 admin center)"
          : "Check your provider's documentation for the correct MX records.",
    },
    {
      num: 3,
      action: "Update or add the MX record",
      detail: instructions.editRecord,
    },
    {
      num: 4,
      action: "Delete any old or incorrect MX records",
      detail: "Multiple MX records can cause mail to be delivered to the wrong place.",
    },
    {
      num: 5,
      action: "Wait 10-30 minutes for DNS propagation",
      detail: "MX changes usually take effect quickly.",
    },
    {
      num: 6,
      action: "Test by sending an email to the domain",
      detail: "Send a test email to an address at this domain and confirm it arrives correctly.",
    },
    {
      num: 7,
      action: "Recheck in the app",
      detail: "Run the Email Security Check again to confirm MX is correct.",
      recheck: true,
    },
  ];

  return {
    summary: "Fix your MX records to ensure email is delivered correctly.",
    steps,
    providerName: provider.name,
  };
}

/**
 * Generate step-by-step fix instructions for SSL/certificate issues.
 */
export function generateSslSteps(check, domain, scanData) {
  const steps = [];
  const code = check.data?.code;

  if (code === "expired" || code === "expiring" || code === "expiring-urgent") {
    steps.push(
      {
        num: 1,
        action: "Renew the SSL certificate immediately",
        detail: code === "expired" ? "The certificate has expired. Visitors see a security warning." : "The certificate expires soon.",
      },
      {
        num: 2,
        action: "Check your hosting provider's SSL/TLS settings",
        detail: "Most hosts offer free Let's Encrypt certificates with auto-renewal.",
      },
      {
        num: 3,
        action: "Enable auto-renewal if available",
        detail: "Prevents this problem from happening again.",
      },
      {
        num: 4,
        action: "Confirm the certificate covers both the domain and www subdomain",
        detail: `Certificate should be valid for ${domain} and www.${domain}`,
      },
      {
        num: 5,
        action: "Wait a few minutes, then test the site",
        detail: `Open https://${domain} and https://www.${domain} in a browser - both should show a padlock with no warnings.`,
      },
      {
        num: 6,
        action: "Recheck in the app",
        detail: "Run the Website Security Check again to confirm the certificate is valid.",
        recheck: true,
      },
    );
  } else {
    steps.push(
      {
        num: 1,
        action: "Enable HTTPS on your website",
        detail: "Contact your hosting provider to install a free SSL certificate (Let's Encrypt).",
      },
      {
        num: 2,
        action: "Ensure the certificate covers both apex and www",
        detail: `Certificate should work for ${domain} and www.${domain}`,
      },
      {
        num: 3,
        action: "Set up auto-renewal",
        detail: "Prevents the certificate from expiring.",
      },
      {
        num: 4,
        action: "Test the site",
        detail: `Visit https://${domain} - you should see a padlock in the browser address bar.`,
      },
      {
        num: 5,
        action: "Recheck in the app",
        detail: "Run the Website Security Check again.",
        recheck: true,
      },
    );
  }

  return {
    summary: code === "expired" ? "Renew your expired SSL certificate immediately." : code?.includes("expiring") ? "Renew your SSL certificate before it expires." : "Install an SSL certificate to enable HTTPS.",
    steps,
  };
}

/**
 * Main entry point: generate step-by-step instructions for any check.
 * Returns { summary, steps: [{num, action, detail?, recordType?, recordName?, recordValue?, recordTTL?, recheck?, warning?}], ... }
 */
export function generateFixSteps(check, domain, scanData, config = {}) {
  const reportAddress = config.reportAddress || "dmarc@example.com";
  
  switch (check.id) {
    case "spf":
      return generateSpfSteps(check, domain, scanData);
    case "dkim":
      return generateDkimSteps(check, domain, scanData);
    case "dmarc":
      return generateDmarcSteps(check, domain, scanData, reportAddress);
    case "email-platform":
      return generateMxSteps(check, domain, scanData);
    case "ssl":
      return generateSslSteps(check, domain, scanData);
    // Add more check types as needed
    default:
      return null;
  }
}
