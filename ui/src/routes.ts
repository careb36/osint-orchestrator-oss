export type AppRoute = {
  path: string;
  label: string;
  title: string;
  description: string;
  showInNav?: boolean;
};

// Single source of truth for the top-level navigation (ui/docs/routes.md).
export const APP_ROUTES: AppRoute[] = [
  {
    path: '/',
    label: 'Overview',
    title: 'Overview',
    description: 'Operational overview and status snapshots.',
    showInNav: true,
  },
  {
    path: '/targets',
    label: 'Targets',
    title: 'Targets',
    description: 'Target inventory, health, and coverage.',
    showInNav: true,
  },
  {
    path: '/runs',
    label: 'Runs',
    title: 'Runs',
    description: 'Recent execution history and current runs.',
    showInNav: true,
  },
];
