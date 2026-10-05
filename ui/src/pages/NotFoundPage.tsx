import { EmptyState, PageLayout } from '../components/PageState';

export function NotFoundPage() {
  return (
    <PageLayout title="Page not found" subtitle="The route you requested does not exist in this shell.">
      <EmptyState title="No matching route" description="Use the navigation above to return to a supported operator view." />
    </PageLayout>
  );
}
