import { Component, type ErrorInfo, type ReactNode } from 'react';
import { reportUiError, trackUiTelemetry } from '../lib/telemetry';

type ErrorBoundaryProps = {
  children: ReactNode;
  fallback?: ReactNode;
};

type ErrorBoundaryState = {
  hasError: boolean;
};

export class AppErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    reportUiError(error, {
      componentStack: errorInfo.componentStack,
      location: window.location.pathname,
    });
    trackUiTelemetry('error_boundary_triggered', {
      message: error.message,
      componentStack: errorInfo.componentStack,
    });
    console.error('Unhandled UI error', error, errorInfo);
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        this.props.fallback ?? (
          <div className="state-card error" role="alert">
            <h2>Something went wrong.</h2>
            <p>The UI hit an unexpected error. Refresh to try again.</p>
          </div>
        )
      );
    }

    return this.props.children;
  }
}
