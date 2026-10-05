import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { Sort, SortDirection } from '../lib/listing';

/**
 * Search, filter and sort state kept in the URL query string, so a filtered
 * view survives a reload and can be shared as a link. A parameter equal to
 * its default is dropped from the URL.
 */
export function useListControls<K extends string>(defaults: Record<string, string>, defaultSort: Sort<K>) {
  const [params, setParams] = useSearchParams();

  const get = useCallback((key: string) => params.get(key) ?? defaults[key] ?? '', [params, defaults]);

  const set = useCallback(
    (key: string, value: string) => {
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          if (value === '' || value === defaults[key]) next.delete(key);
          else next.set(key, value);
          return next;
        },
        { replace: true },
      );
    },
    [setParams, defaults],
  );

  const raw = params.get('sort');
  const sort = useMemo<Sort<K>>(() => {
    const [rawKey, rawDir] = raw ? raw.split(':') : [];
    return {
      key: (rawKey as K) || defaultSort.key,
      dir: rawDir === 'asc' || rawDir === 'desc' ? rawDir : defaultSort.dir,
    };
  }, [raw, defaultSort.key, defaultSort.dir]);

  /** Clicking an active column flips the direction; a new column starts with its natural direction. */
  const toggleSort = useCallback(
    (key: K, naturalDir: SortDirection = 'asc') => {
      const dir: SortDirection = sort.key === key ? (sort.dir === 'asc' ? 'desc' : 'asc') : naturalDir;
      const value = key === defaultSort.key && dir === defaultSort.dir ? '' : `${key}:${dir}`;
      set('sort', value);
    },
    [sort, set, defaultSort],
  );

  const clear = useCallback(() => setParams(new URLSearchParams(), { replace: true }), [setParams]);
  const isFiltered = Array.from(params.keys()).some((key) => key !== 'sort');

  return { get, set, sort, toggleSort, clear, isFiltered };
}
