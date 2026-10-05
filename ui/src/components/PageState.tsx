import type { ReactNode } from 'react';

type PageLayoutProps = {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
};

export function PageLayout({ title, subtitle, actions, children }: PageLayoutProps) {
  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Operations</p>
          <h1>{title}</h1>
          {subtitle ? <p className="lede">{subtitle}</p> : null}
        </div>
        {actions ? <div className="page-actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}

type StateCardProps = {
  title: string;
  description: string;
  tone?: 'warning' | 'error' | 'info';
  action?: ReactNode;
};

export function StateCard({ title, description, tone = 'info', action }: StateCardProps) {
  return (
    <div className={`state-card ${tone}`} role={tone === 'error' || tone === 'warning' ? 'alert' : undefined}>
      <h2>{title}</h2>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function LoadingState({ message }: { message: string }) {
  return (
    <div className="state-card info" role="status" aria-live="polite">
      <p>{message}</p>
    </div>
  );
}

export function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return <StateCard title={title} description={description} tone="info" action={action} />;
}

export function ErrorState({ title = 'Unable to load this view', description, action }: { title?: string; description: string; action?: ReactNode }) {
  return <StateCard title={title} description={description} tone="error" action={action} />;
}
