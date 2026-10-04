# UX acceptance checklist

## Baseline requirements

- [ ] The app uses a clear top-level shell with consistent navigation labels.
- [ ] Each route supports a loading state and a fallback empty/error state.
- [ ] Unexpected runtime errors are captured by a global error boundary.
- [ ] The UI reads from a typed API client instead of ad hoc fetch calls.
- [ ] The design language remains readable and low-noise across screens.

## Accessibility and responsiveness

- [ ] Content structure uses semantic headings and navigation landmarks.
- [ ] Key actions and labels remain legible on narrow screens.
- [ ] Error and warning states are visible and understandable without context.

## Ready for follow-on slices

- [ ] New views can be added without changing the entire application shell.
- [ ] Query patterns are consistent and support future stale/error handling.
- [ ] Product decisions are documented so design and engineering stay aligned.
