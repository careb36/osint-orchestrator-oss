import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { LocaleProvider } from '../i18n';
import { uiTelemetry } from '../lib/telemetry';
import { AppErrorBoundary } from './ErrorBoundary';

function Crashing({ when }: { when: boolean }) {
  if (when) throw new Error('view exploded');
  return <p>view content</p>;
}

const wrap = (node: React.ReactNode) =>
  render(
    <MemoryRouter>
      <LocaleProvider initialLocale="en">{node}</LocaleProvider>
    </MemoryRouter>,
  );

describe('AppErrorBoundary', () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    uiTelemetry.length = 0;
  });
  afterEach(() => {
    errorSpy.mockRestore();
  });

  it('shows a fallback with a way out and records the crash', async () => {
    wrap(
      <AppErrorBoundary>
        <Crashing when={true} />
      </AppErrorBoundary>,
    );
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('Something went wrong.');
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /back to the overview/i })).toHaveAttribute('href', '/');
    expect(uiTelemetry.map((entry) => entry.event)).toEqual(['ui_error', 'error_boundary_triggered']);
    expect(uiTelemetry[0].detail.message).toBe('view exploded');
  });

  it('renders the children again on retry', async () => {
    const user = userEvent.setup();
    let crash = true;
    const Child = () => <Crashing when={crash} />;
    wrap(
      <AppErrorBoundary>
        <Child />
      </AppErrorBoundary>,
    );
    screen.getByRole('alert');
    crash = false;
    await user.click(screen.getByRole('button', { name: /try again/i }));
    expect(screen.getByText('view content')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('recovers when the reset key changes, as it does when the route changes', () => {
    const view = wrap(
      <AppErrorBoundary resetKey="/runs/1">
        <Crashing when={true} />
      </AppErrorBoundary>,
    );
    screen.getByRole('alert');
    view.rerender(
      <MemoryRouter>
        <LocaleProvider initialLocale="en">
          <AppErrorBoundary resetKey="/runs/2">
            <Crashing when={false} />
          </AppErrorBoundary>
        </LocaleProvider>
      </MemoryRouter>,
    );
    expect(screen.getByText('view content')).toBeInTheDocument();
  });
});
