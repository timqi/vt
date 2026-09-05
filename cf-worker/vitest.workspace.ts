// Two suites, one `npm test`: the runtime-free unit tests on plain vitest, and
// the AccountDO tests inside workerd via @cloudflare/vitest-pool-workers. The
// pool needs its own environment, so they cannot share a single project config.
export default ['./vitest.node.config.ts', './vitest.config.ts'];
