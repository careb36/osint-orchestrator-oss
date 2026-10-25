export type AppRoute = {
  path: string;
  /** Catalogue key of the navigation label (src/i18n.tsx). */
  labelKey: 'nav.overview' | 'nav.targets' | 'nav.runs' | 'nav.alerts' | 'nav.cases' | 'nav.account';
  showInNav?: boolean;
  personalOnly?: boolean;
};

// Single source of truth for the top-level navigation (ui/docs/routes.md).
export const APP_ROUTES: AppRoute[] = [
  { path: '/cases', labelKey: 'nav.cases', showInNav: true, personalOnly: true },
  { path: '/', labelKey: 'nav.overview', showInNav: true },
  { path: '/targets', labelKey: 'nav.targets', showInNav: true },
  { path: '/runs', labelKey: 'nav.runs', showInNav: true },
  { path: '/alerts', labelKey: 'nav.alerts', showInNav: true },
  { path: '/account', labelKey: 'nav.account', showInNav: true, personalOnly: true },
];
