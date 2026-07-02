import * as assert from "assert";
import * as path from "path";

import {
  explorerCsp,
  hardenWebviewHtml,
  isPathInside,
  parseExplorerMessage,
} from "../../webviewSecurity";

// Regression coverage for the publish-blocking webview hardening (v0.21.10
// initiative 2): the strict CSP on the Explorer webview, the validated bridge
// envelope, and the workspace path confinement. Pure functions — no live
// editor needed (same pattern as claudeHook.test.ts).

const CSP_SOURCE = "vscode-resource://test-source";

suite("Explorer webview CSP", () => {
  test("denies everything by default and grants no network", () => {
    const csp = explorerCsp(CSP_SOURCE);
    assert.ok(csp.startsWith("default-src 'none'"), "default-src 'none' leads");
    assert.ok(!csp.includes("connect-src"), "no connect-src — no exfiltration channel");
    assert.ok(!csp.includes("unsafe-eval"), "eval is not granted");
  });

  test("permits the webview's own resource origin", () => {
    const csp = explorerCsp(CSP_SOURCE);
    for (const directive of ["img-src", "font-src", "style-src", "script-src"]) {
      assert.ok(
        csp.includes(`${directive} ${CSP_SOURCE}`),
        `${directive} grants the cspSource`,
      );
    }
  });

  test("injects the CSP meta as the first child of <head>", () => {
    const html = "<html><head><title>Portal</title></head><body></body></html>";
    const hardened = hardenWebviewHtml(html, CSP_SOURCE);
    const head = hardened.indexOf("<head>");
    const meta = hardened.indexOf('<meta http-equiv="Content-Security-Policy"');
    const title = hardened.indexOf("<title>");
    assert.ok(meta > head, "meta is inside head");
    assert.ok(meta < title, "meta precedes all other head children");
    assert.ok(hardened.includes("default-src 'none'"), "the strict policy is present");
  });

  test("still applies a CSP when the document has no <head>", () => {
    const hardened = hardenWebviewHtml("<p>bare fragment</p>", CSP_SOURCE);
    assert.ok(
      hardened.startsWith('<meta http-equiv="Content-Security-Policy"'),
      "meta is prepended to a head-less document",
    );
  });
});

suite("Explorer bridge message envelope", () => {
  test("accepts exactly the known shapes", () => {
    assert.deepStrictEqual(parseExplorerMessage({ type: "ready" }), { kind: "ready" });
    assert.deepStrictEqual(parseExplorerMessage({ type: "open-artifact", id: "RAC-1" }), {
      kind: "open-artifact",
      id: "RAC-1",
    });
  });

  test("ignores forged and malformed messages", () => {
    const forged: unknown[] = [
      null,
      undefined,
      "open-artifact",
      42,
      { type: "evil-command" },
      { type: "open-artifact" }, // no id
      { type: "open-artifact", id: 42 }, // non-string id
      { type: "open-artifact", id: "" }, // empty id
      { type: ["open-artifact"], id: "RAC-1" }, // non-string type
    ];
    for (const message of forged) {
      assert.deepStrictEqual(
        parseExplorerMessage(message),
        { kind: "ignored" },
        `rejected: ${JSON.stringify(message)}`,
      );
    }
  });

  test("an id is an opaque token for export resolution, never a path", () => {
    // Even a path-shaped id parses as an id only; the host resolves it against
    // the engine's export and confines the resulting path (isPathInside).
    const parsed = parseExplorerMessage({ type: "open-artifact", id: "../../etc/passwd" });
    assert.deepStrictEqual(parsed, { kind: "open-artifact", id: "../../etc/passwd" });
  });
});

suite("Workspace path confinement", () => {
  const root = path.resolve(path.sep, "workspace", "corpus");

  test("accepts paths strictly inside the root", () => {
    assert.ok(isPathInside(root, path.join(root, "rac", "decisions", "adr-001.md")));
  });

  test("rejects the root itself, escapes, and outside paths", () => {
    assert.ok(!isPathInside(root, root), "the root itself is not inside");
    assert.ok(
      !isPathInside(root, path.join(root, "..", "other", "file.md")),
      "a ..-escape is rejected",
    );
    assert.ok(
      !isPathInside(root, path.resolve(path.sep, "etc", "passwd")),
      "an absolute outside path is rejected",
    );
  });
});
