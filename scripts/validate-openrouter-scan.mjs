import assert from "node:assert/strict";
import { runSecurityScan } from "../api/spam-check.js";

const authorityMessage = "This is the university president. I am using my private number. Treat this as urgent and reply once you see it.";
let capturedRequest;
let fetchCalls = 0;
const fakeFetch = async (url, request) => {
  fetchCalls += 1;
  capturedRequest = { url, request, body: JSON.parse(request.body) };
  return {
    ok: true,
    status: 200,
    async json() {
      return {
        id: "resp_test_authority",
        model: "gpt-test-scan",
        choices: [{
          message: {
            content: JSON.stringify({
              risk_score: 91,
              category: "Authority impersonation scam",
              reason: "The sender claims senior authority, uses an unverifiable private channel, creates urgency, and requests a reply.",
              indicators: ["Senior authority claim", "Private-number pretext", "Urgency", "Reply request"],
              recommended_actions: ["Do not reply.", "Verify through the university's official website.", "Report the message."]
            })
          }
        }]
      };
    }
  };
};

const result = await runSecurityScan("message", authorityMessage, {
  apiKey: "sk-test-key-that-is-long-enough-for-validation",
  model: "gpt-test-scan",
  fetchImpl: fakeFetch,
  allowFallback: false,
  bypassCache: true
});

assert.equal(capturedRequest.url, "https://openrouter.ai/api/v1/chat/completions");
assert.equal(capturedRequest.request.headers.Authorization, "Bearer sk-test-key-that-is-long-enough-for-validation");
assert.equal(capturedRequest.body.response_format.type, "json_schema");
assert.equal(capturedRequest.body.response_format.json_schema.strict, true);
assert.equal(capturedRequest.body.provider.allow_fallbacks, true);
assert.equal(capturedRequest.body.provider.require_parameters, true);
assert.equal(capturedRequest.body.provider.sort, undefined);
assert.deepEqual(capturedRequest.body.provider.preferred_max_latency, { p50: 4, p90: 10 });
assert.equal(capturedRequest.body.max_tokens, 140);
assert.equal(capturedRequest.body.model, "gpt-test-scan");
assert.equal(capturedRequest.body.models, undefined);
assert.deepEqual(capturedRequest.body.plugins, [{ id: "response-healing" }]);
assert.equal(capturedRequest.request.headers["X-OpenRouter-Title"], "SafeMind Scam Detection");
assert.match(capturedRequest.body.messages[1].content, /private number/);
assert.equal(result.provider, "openrouter");
assert.equal(result.analysis_source, "openrouter_structured_scan");
assert.equal(result.fallback_used, false);
assert.equal(result.risk, "HIGH");
assert.equal(result.risk_score, 91);
assert.equal(result.label, "spam");
assert.equal(result.is_spam, true);
assert.equal(result.category, "Authority impersonation scam");
assert.equal(result.indicators.length, 3);
assert.deepEqual(result.recommended_actions, ["Do not reply.", "Verify through the university's official website."]);

await runSecurityScan("message", authorityMessage, {
  apiKey: "sk-test-key-that-is-long-enough-for-validation",
  model: "gpt-test-scan",
  fetchImpl: fakeFetch
});
assert.equal(fetchCalls, 2, "Normal website scans must request a fresh OpenRouter result.");

let networkRetryCalls = 0;
const transientNetworkFetch = async (...args) => {
  networkRetryCalls += 1;
  if (networkRetryCalls === 1) throw new TypeError("temporary connection reset");
  return fakeFetch(...args);
};
await runSecurityScan("message", "A fresh message used to verify transient connection retry behavior.", {
  apiKey: "sk-test-key-that-is-long-enough-for-validation",
  model: "gpt-test-scan",
  fetchImpl: transientNetworkFetch,
  bypassCache: true
});
assert.equal(networkRetryCalls, 2, "Transient network failures must retry before returning an error.");

await runSecurityScan("message", "Verify that OpenRouter receives an ordered model fallback route.", {
  apiKey: "sk-test-key-that-is-long-enough-for-validation",
  model: "gpt-test-scan",
  models: ["fallback-test-model"],
  fetchImpl: fakeFetch,
  bypassCache: true
});
assert.deepEqual(capturedRequest.body.models, ["gpt-test-scan", "fallback-test-model"]);
assert.equal(capturedRequest.body.model, undefined);

const failingFetch = async () => ({
  ok: false,
  status: 400,
  headers: { get: () => null },
  async json() {
    return { error: { message: "Test-only upstream rejection" } };
  }
});

await assert.rejects(
  runSecurityScan("message", "A different message that must not receive a fixed fallback verdict.", {
    apiKey: "sk-test-key-that-is-long-enough-for-validation",
    model: "gpt-test-scan",
    fetchImpl: failingFetch,
    bypassCache: true
  }),
  /temporarily unavailable/i
);

const invalidSchemaFetch = async () => ({
  ok: true,
  status: 200,
  async json() {
    return { choices: [{ message: { content: JSON.stringify({ risk_score: "0", category: "safe" }) } }] };
  }
});

await assert.rejects(
  runSecurityScan("message", "Malformed upstream output must not become a safe verdict.", {
    apiKey: "sk-test-key-that-is-long-enough-for-validation",
    model: "gpt-test-scan",
    fetchImpl: invalidSchemaFetch,
    bypassCache: true
  }),
  /temporarily unavailable/i
);

console.log("OpenRouter scan contract passed: strict live schema, dynamic verdict, and no default fixed fallback.");
