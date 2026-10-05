import { EmptyState, PageLayout } from '../components/PageState';
import { useLocale } from '../i18n';

export function NotFoundPage() {
  const { t } = useLocale();
  return (
    <PageLayout title={t('notFound.title')} subtitle={t('notFound.subtitle')}>
      <EmptyState title={t('notFound.emptyTitle')} description={t('notFound.emptyBody')} />
    </PageLayout>
  );
}
