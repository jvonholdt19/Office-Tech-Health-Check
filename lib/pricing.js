// The admin pricing sheet: every price and offer from lib/config.js (the single source of truth),
// with display labels. Internal: served only to admins by /api/pricing, never to client plans.
import { PACKAGES, RECURRING_OPTIONS, FOUNDING_OFFER, QUOTE_ITEMS, PRICES_APPROVED } from "./config.js";
import { formatPrice, periodLabel } from "./plan.js";

export function pricingSheet({ packages = PACKAGES, recurring = RECURRING_OPTIONS, founding = FOUNDING_OFFER, quotes = QUOTE_ITEMS, approved = PRICES_APPROVED } = {}) {
  const foundingPackage = founding ? packages.find((p) => p.id === founding.packageId) : null;
  const bonus = founding ? recurring.find((r) => r.id === founding.bonusRecurringId) : null;
  return {
    approved,
    packages: packages.map((p) => ({ id: p.id, name: p.name, label: formatPrice(p.price), scope: p.scope, blurb: p.blurb })),
    recurring: recurring.map((r) => ({ id: r.id, name: r.name, label: periodLabel(r.price, r.period), blurb: r.blurb })),
    founding: founding
      ? {
          name: founding.name,
          label: formatPrice(founding.price),
          packageName: foundingPackage?.name || founding.packageId,
          regularLabel: foundingPackage ? formatPrice(foundingPackage.price) : null,
          bonus: bonus ? { name: bonus.name, regularLabel: periodLabel(bonus.price, bonus.period) } : null,
          limit: founding.limit,
          terms: founding.terms,
          note: founding.adminNote || null,
        }
      : null,
    quotes: Object.entries(quotes).map(([id, q]) => ({ id, title: q.title, label: `Quote, from ${formatPrice(q.from)}` })),
  };
}
