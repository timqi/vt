// DO storage accepts at most 128 keys/pairs per get(), put(), or delete().
export const STORAGE_BATCH = 128;
// Entries requested per list() page when streaming a key prefix.
const LIST_PAGE = 1000;

// Return the count storage actually removed; a failed batch must reject even
// when earlier batches succeeded, never report partial cleanup as complete.
export async function deleteKeysBatched(
  storage: { delete(keys: string[]): Promise<number> }, keys: string[],
): Promise<number> {
  let deleted = 0;
  for (let i = 0; i < keys.length; i += STORAGE_BATCH) {
    deleted += await storage.delete(keys.slice(i, i + STORAGE_BATCH));
  }
  return deleted;
}

// Stream one key prefix page by page. Only an empty page ends the scan: DO
// storage may cut a page below LIST_PAGE to stay under its response-size cap, so
// a short nonempty page is not the end of the prefix (the cost is one extra empty
// list() per scan). `startAfter` is a key VALUE, not an index, so a caller may
// delete keys the cursor already passed without skipping anything.
export async function* listPrefixPages<T>(
  storage: Pick<DurableObjectStorage, 'list'>, prefix: string,
): AsyncGenerator<Map<string, T>> {
  let startAfter: string | undefined;
  for (;;) {
    const page = await storage.list<T>({ prefix, limit: LIST_PAGE, startAfter });
    if (page.size === 0) return;
    yield page;
    for (const key of page.keys()) startAfter = key;
  }
}
