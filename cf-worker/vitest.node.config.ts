// Plain-vitest project: the runtime-free unit tests.
//
// These cover pure logic (b64u, TTL policy arithmetic, credential parsing,
// notification string builders) and deliberately need no workerd — they are the
// fast gate. Keeping them out of the Workers pool preserves that.

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'node',
    include: [
      'test/cache_policy.test.ts',
      'test/credentials.test.ts',
      'test/crypto.test.ts',
      'test/notify.test.ts',
    ],
  },
});
