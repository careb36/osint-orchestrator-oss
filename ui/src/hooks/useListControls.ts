import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { Sort, SortDirection } from '../lib/listing';

export type ListControlsOptions<K extends string> = {
  /** Default value per key; a parameter equal to its default is dropped from the URL. */
  defaults: Record<string, string>;
  defaultSort: Sort<K>;
  /** Columns the view can sort by; an unknown key in the URL falls back to the default sort. */
  sortKeys: readonly K[];
  /**
   * Allowed values per key. A value in the URL outside the list reads as the
   * default, so a stale or hand-edited link degrades to the plain view
   * instead of a select with no matching option. Keys without a list (free
   * text) are passed through.
   */
  allowed?: Record<string, readonly string[]>;
};

/**
 * Search, filter and sort state kept in the URL query string, so a filtered
 * view survives a reload and can be shared as a link.
 */
export function useListControls<K extends string>({ defaults, defaultSort, sortKeys, allowed = {} }: ListControlsOptions<K>) {
  const [params, setParams] = useSearchParams();

  const get = useCallback(
    (key: string) => {
      const fallback = defaults[key] ?? '';
      const value = params.get(key);
      if (value === null) return fallback;
      const options = allowed[key];
      return options && !options.includes(value) ? fallback : value;
    },
    [params, defaults, allowed],
  );

  const apply = useCallback(
    (changes: Record<string, string>) => {
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          for (const [key, value] of Object.entries(changes)) {
            if (value === '' || value === defaults[key]) next.delete(key);
            else next.set(key, value);
          }
          return next;
        },
        { replace: true },
      );
    },
    [setParams, defaults],
  );

  const set = useCallback((key: string, value: string) => apply({ [key]: value }), [apply]);

  /** Reset several keys in one navigation (two consecutive set() calls would race on the same snapshot). */
  const clearKeys = useCallback((keys: readonly string[]) => apply(Object.fromEntries(keys.map((key) => [key, '']))), [apply]);

  /** True when any of the given keys differs from its default. */
  const isAnySet = useCallback((keys: readonly string[]) => keys.some((key) => get(key) !== (defaults[key] ?? '')), [get, defaults]);

  const raw = params.get('sort');
  const sort = useMemo<Sort<K>>(() => {
    const [rawKey, rawDir] = raw ? raw.split(':') : [];
    const key = (sortKeys as readonly string[]).includes(rawKey ?? '') ? (rawKey as K) : defaultSort.key;
    return {
      key,
      dir: rawDir === 'asc' || rawDir === 'desc' ? rawDir : defaultSort.dir,
    };
  }, [raw, sortKeys, defaultSort.key, defaultSort.dir]);

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
  const isFiltered = isAnySet(Object.keys(defaults));

  return { get, set, clearKeys, isAnySet, sort, toggleSort, clear, isFiltered };
}
