// DO storage accepts at most 128 keys/pairs per get(), put(), or delete().
export const STORAGE_BATCH = 128;

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
