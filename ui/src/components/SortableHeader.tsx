import type { Sort, SortDirection } from '../lib/listing';

type Props<K extends string> = {
  label: string;
  column: K;
  sort: Sort<K>;
  onSort: (key: K, naturalDir?: SortDirection) => void;
  /** Direction a first click on this column uses. */
  naturalDir?: SortDirection;
};

/** A column header that sorts the table; aria-sort tells assistive technology the current order. */
export function SortableHeader<K extends string>({ label, column, sort, onSort, naturalDir = 'asc' }: Props<K>) {
  const active = sort.key === column;
  const ariaSort = active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none';
  return (
    <th role="columnheader" scope="col" aria-sort={ariaSort}>
      <button type="button" className="sort-button" onClick={() => onSort(column, naturalDir)}>
        {label}
        <span aria-hidden="true" className="sort-indicator">
          {active ? (sort.dir === 'asc' ? ' ▲' : ' ▼') : ''}
        </span>
      </button>
    </th>
  );
}
