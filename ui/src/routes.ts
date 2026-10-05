export type AppRoute = {
  path: string;
  label: string;
  title: string;
  description: string;
  showInNav?: boolean;
};

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

export const QUICK_ACTIONS = [
  { label: 'Review runs', to: '/runs' },
  { label: 'Inspect targets', to: '/targets' },
];
