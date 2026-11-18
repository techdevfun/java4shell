/**
 * Live smoke tests (blueprint section 6).
 * Soft-skip on network failure: these assert the pre-creation state
 * (npm + GitHub names still free, advisories live), never hard-fail CI.
 */
import test from "node:test";
import assert from "node:assert/strict";

async function getStatus(url, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: ctrl.signal,
      redirect: "follow",
    });
    return res.status;
  } finally {
    clearTimeout(t);
  }
}

test("live: npm package name `java4shell` is still unclaimed (404)", async (t) => {
  let status;
  try {
    status = await getStatus("https://registry.npmjs.org/java4shell");
  } catch {
    t.skip("network unavailable - cannot verify npm name");
    return;
  }
  assert.equal(status, 404, `expected npm 404 for java4shell, got ${status}`);
});

test("live: GitHub repo techdevfun/java4shell does not exist yet (404)", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://api.github.com/repos/techdevfun/java4shell",
    );
  } catch {
    t.skip("network unavailable - cannot verify GitHub name");
    return;
  }
  // Unauthenticated API may rate-limit (403); that is not a 404 and
  // must not fail the test - it only means the check could not run.
  if (status === 403) {
    t.skip("GitHub API rate-limited (403) - cannot verify repo name");
    return;
  }
  assert.equal(
    status,
    404,
    `expected GitHub 404 for techdevfun/java4shell, got ${status}`,
  );
});

test("live: Calif Java4Shell write-up is reachable (200)", async (t) => {
  let status;
  try {
    status = await getStatus("https://calif.io/java4shell/");
  } catch {
    t.skip("network unavailable - cannot verify Calif write-up");
    return;
  }
  assert.equal(status, 200, `expected Calif 200, got ${status}`);
});

test("live: CISA alert is reachable (200)", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching",
    );
  } catch {
    t.skip("network unavailable - cannot verify CISA alert");
    return;
  }
  assert.equal(status, 200, `expected CISA 200, got ${status}`);
});

test("live: OpenJDK vulnerability advisories index is reachable (200)", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://openjdk.org/groups/vulnerability/advisories/",
    );
  } catch {
    t.skip("network unavailable - cannot verify OpenJDK advisories");
    return;
  }
  assert.equal(status, 200, `expected OpenJDK 200, got ${status}`);
});
