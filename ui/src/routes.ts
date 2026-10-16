export type AppRoute = {
  path: string;
  /** Catalogue key of the navigation label (src/i18n.tsx). */
  labelKey: 'nav.overview' | 'nav.targets' | 'nav.runs' | 'nav.alerts';
  showInNav?: boolean;
};

// Single source of truth for the top-level navigation (ui/docs/routes.md).
export const APP_ROUTES: AppRoute[] = [
  { path: '/', labelKey: 'nav.overview', showInNav: true },
  { path: '/targets', labelKey: 'nav.targets', showInNav: true },
  { path: '/runs', labelKey: 'nav.runs', showInNav: true },
  { path: '/alerts', labelKey: 'nav.alerts', showInNav: true },
];
