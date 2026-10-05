import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { ApiKeyProvider } from './auth';
import { LocaleProvider } from './i18n';
import './styles.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: false,
    },
  },
});

// Vite's BASE_URL is "/console/"; the router wants it without the slash.
const basename = import.meta.env.BASE_URL.replace(/\/$/, '');

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter basename={basename}>
        <LocaleProvider>
          <ApiKeyProvider>
            <App />
          </ApiKeyProvider>
        </LocaleProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
