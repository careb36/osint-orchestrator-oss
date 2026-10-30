export type AppRoute = {
  path: string;
  /** Catalogue key of the navigation label (src/i18n.tsx). */
  labelKey: 'nav.overview' | 'nav.targets' | 'nav.runs' | 'nav.alerts' | 'nav.cases' | 'nav.account';
  showInNav?: boolean;
  personalOnly?: boolean;
};

// Single source of truth for the top-level navigation (ui/docs/routes.md).
//
// Order carries meaning (Serial Position Effect): the slot an operator looks at
// first is the one they remember, so the landing route `/` leads, day-to-day
// work follows in the order it is performed, and the personal destinations —
// which are also the only conditional ones — close the list. The route map in
// ui/docs/routes.md reads in this order; navigation.test.tsx holds the two
// together.
export const APP_ROUTES: AppRoute[] = [
  { path: '/', labelKey: 'nav.overview', showInNav: true },
  { path: '/targets', labelKey: 'nav.targets', showInNav: true },
  { path: '/runs', labelKey: 'nav.runs', showInNav: true },
  { path: '/alerts', labelKey: 'nav.alerts', showInNav: true },
  { path: '/cases', labelKey: 'nav.cases', showInNav: true, personalOnly: true },
  { path: '/account', labelKey: 'nav.account', showInNav: true, personalOnly: true },
];
