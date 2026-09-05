// Workers-pool project: the Durable Object tests.
//
// AccountDO owns the DEK-cache lifecycle (writeCache, opCacheList,
// opCacheExtendCreate, opApprove → commitExtend) and can only be exercised
// against a real DO runtime — SQLite storage, the input gate, and the
// serialization the concurrency comments depend on. So these run inside workerd
// via @cloudflare/vitest-pool-workers, wired to the committed
// `wrangler.test.toml` (the real wrangler.toml is gitignored and must never be a
// test dependency).
//
// The pure unit tests stay on plain vitest — see vitest.node.config.ts and the
// vitest.workspace.ts that runs both under one `npm test`.

import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
  test: {
    name: 'workers',
    include: ['test/do_account.*.test.ts'],
    poolOptions: {
      workers: {
        // Each test file gets its own storage stack, undone after every test:
        // these tests write cache entries and audit rows into a SINGLETON DO
        // (idFromName('account')), so without this a leftover `dek:` entry from
        // one test would silently widen the next one's scan.
        isolatedStorage: true,
        singleWorker: true,
        wrangler: { configPath: './wrangler.test.toml' },
      },
    },
  },
});
