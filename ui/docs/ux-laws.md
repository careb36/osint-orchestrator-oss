# UX laws applied to the dashboard

The dashboard follows [Laws of UX](https://lawsofux.com/) where a law makes a
concrete, checkable difference to an operator working under time pressure. This
document records which ones are applied, where the decision lives, and what
holds it in place, so a later change can tell a deliberate decision from an
accident. It is not a style guide: a law is listed only if the code applies it
and a test or a type enforces it.

## Applied

| Law | Decision | Lives in | Held by |
| --- | --- | --- | --- |
| Serial Position Effect | The landing route `/` takes the first navigation slot, day-to-day views follow in the order they are used, and the personal destinations close the list. The order in the route map is authoritative. | `src/routes.ts` | `src/navigation.test.tsx` parses `ui/docs/routes.md` and compares it with `APP_ROUTES` |
| Law of Similarity | Every rail entry carries a glyph, and the glyph column has a fixed width, so the six entries read as one group and the labels share a left edge. | `src/App.tsx` (`RAIL_ICONS`), `src/styles.css` (`.rail-icon`) | `src/navigation.test.tsx`: no entry may render an empty glyph slot |
| Von Restorff Effect | The overview sorts targets by attention tier, so what needs a human leads the table and a calm target never sits above an at-risk one. | `src/lib/overview.ts` (`ATTENTION`, `buildTargetRows`) | `src/lib/overview.test.ts` |
| Doherty Threshold | A click is answered immediately and attributably: the row whose run was started says so, while the other rows are only disabled. | `src/hooks/useStartRun.ts` (`isPendingFor`) | `src/App.test.tsx`, "names the row that is starting, one row only" |
| Fitts's Law | Interactive targets keep a comfortable hit area: 32 px buttons, 28 px inside dense tables, and under 860 px wide tables become stacked cards so an action is never a narrow column. | `src/styles.css` (`.primary-action`, `.ghost-button`, `.data-table .ghost-button`, `@media (max-width: 860px)`) | visual inspection; no automated check |
| Jakob's Law | The shell keeps the conventions an operator already knows: a left rail, links to detail pages, search and filters in the URL query string, tables with sortable headers. | `src/App.tsx`, `src/hooks/useListControls.ts` | `src/App.test.tsx` renders a filtered, sorted route from its query string; `src/lib/listing.test.ts` covers the filtering and sorting itself |
| Zeigarnik Effect | Unfinished work is surfaced instead of finished work: active runs have their own table above the findings, and a target with no run is labelled "never" rather than omitted. | `src/pages/HomePage.tsx` | `src/App.test.tsx`, `src/lib/overview.test.ts` |

## Considered and left out

Recording the rejections matters as much as the applications: an operator
dashboard is not a consumer product, and several laws pull in the wrong
direction here.

- **Aesthetic-Usability Effect.** A polished look buys tolerance for friction.
  The friction this tool removes is a missed risk, so the design spends its
  effort on legibility of state, not on decoration.
- **Choice Overload and Hick's Law.** Both argue for fewer options. The
  navigation is already six entries and the pages carry the filters they need;
  cutting further would hide a capability rather than simplify a decision. The
  protection applied instead is that the overview decides what leads, so the
  operator does not have to compare six views to find the urgent one.
- **Miller's Law.** The "seven plus or minus two" figure is usually misapplied
  to menus. Chunking is applied where it pays — grouped KPI cards, one section
  per question — without treating seven as a limit.
- **Goal-Gradient Effect, Flow, Peak-End Rule.** These describe long interactive
  sessions. An operator visits for a few minutes to answer one question; the
  useful equivalent here is a state that is legible on arrival, which the
  overview covers.
- **Parkinson's Law and Tesler's Law.** Both are about work expanding to fill the
  space available; the dashboard does not pace or time-box an operator's work,
  and the irreducible complexity of OSINT qualification is not hidden behind a
  simplified control.
- **Postel's Law.** Acceptance of malformed input belongs in the API, not in a
  client that would then have to guess what a server meant. The dashboard
  renders the server's `detail` as an attributed secondary line instead
  (`src/components/RunNotice.tsx`).
