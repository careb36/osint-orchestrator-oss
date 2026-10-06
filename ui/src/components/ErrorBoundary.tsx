import { Component, type ErrorInfo, type ReactNode } from 'react';
import { reportUiError, trackUiTelemetry } from '../lib/telemetry';
import { ErrorFallback } from './ErrorFallback';

type ErrorBoundaryProps = {
  children: ReactNode;
  fallback?: ReactNode;
  /**
   * When this value changes while the fallback is showing, the boundary
   * clears its error and renders its children again. The app passes the
   * route path, so leaving a view that crashed recovers the shell.
   */
  resetKey?: string;
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

  componentDidUpdate(previous: ErrorBoundaryProps): void {
    if (this.state.hasError && previous.resetKey !== this.props.resetKey) {
      this.setState({ hasError: false });
    }
  }

  retry = (): void => {
    this.setState({ hasError: false });
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return this.props.fallback ?? <ErrorFallback onRetry={this.retry} />;
    }

    return this.props.children;
  }
}
