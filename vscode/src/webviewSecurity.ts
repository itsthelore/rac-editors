/**
 * Webview security seams for the RAC Explorer (v0.21.10 initiative 2).
 *
 * Pure, vscode-free helpers so the publish-blocking hardening contract is
 * unit-testable outside the extension host (same pattern as claudeHook.ts):
 * the strict CSP applied to the exported Portal HTML, the validated message
 * envelope for the webview → host bridge, and the workspace path confinement
 * that `open-artifact` resolution relies on.
 */

import * as path from "node:path";

/**
 * A strict Content-Security-Policy for the Explorer webview. The exported
 * Portal is self-contained — inline scripts and styles, data: fonts and
 * images, and no network — so `default-src 'none'` blocks any exfiltration
 * (there is no connect-src). Inline script/style and data: assets keep the
 * offline viewer working; the vendored shell uses no eval/WebAssembly, so
 * 'unsafe-eval' is deliberately not granted. `cspSource` is included so
 * VS Code's own injected webview resources (e.g. the `acquireVsCodeApi`
 * bridge the sync relies on) are permitted.
 */
export function explorerCsp(cspSource: string): string {
  return [
    "default-src 'none'",
    `img-src ${cspSource} data:`,
    `font-src ${cspSource} data:`,
    `style-src ${cspSource} 'unsafe-inline'`,
    `script-src ${cspSource} 'unsafe-inline'`,
  ].join("; ");
}

/** Insert the CSP as the first child of <head> so it governs the whole document. */
export function hardenWebviewHtml(html: string, cspSource: string): string {
  const meta = `<meta http-equiv="Content-Security-Policy" content="${explorerCsp(cspSource)}">`;
  return html.includes("<head>")
    ? html.replace("<head>", `<head>${meta}`)
    : `${meta}${html}`;
}

/**
 * The validated message envelope for the Explorer bridge. Anything that is
 * not exactly a known shape is `ignored` — the host acts only on `ready` and
 * on `open-artifact` with a non-empty string id (which is then resolved
 * against the engine's export, never used as a path).
 */
export type ExplorerMessage =
  | { kind: "ready" }
  | { kind: "open-artifact"; id: string }
  | { kind: "ignored" };

export function parseExplorerMessage(message: unknown): ExplorerMessage {
  if (typeof message !== "object" || message === null) return { kind: "ignored" };
  const type = (message as { type?: unknown }).type;
  if (type === "ready") return { kind: "ready" };
  if (type === "open-artifact") {
    const id = (message as { id?: unknown }).id;
    if (typeof id === "string" && id.length > 0) return { kind: "open-artifact", id };
  }
  return { kind: "ignored" };
}

/**
 * True when `target` is strictly inside `root` (both file-system paths):
 * not root itself, no `..` escape, no absolute jump. The confinement check
 * behind opening artifact paths from the webview.
 */
export function isPathInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}
