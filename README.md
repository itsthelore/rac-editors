# rac-editors

IDE / editor integrations for [RAC](https://github.com/itsthelore/rac-core)
(requirements-as-code) — one subdir per client. Per ADR-092 (one repo per
concern, subdir per member) this is the single home for the editor clients;
future editors (for example `jetbrains/`) land as sibling subdirs.

The repository takes the uniform `rac-*` slug; the published extension still
**lists** as "Lore for VS Code" — the brand lives at the marketplace listing, not
the repository name (ADR-092).

## Members

| Subdir | Client |
| --- | --- |
| [`vscode/`](vscode/) | VS Code / Cursor extension ("Lore for VS Code") |

## History

`vscode/` is the former **`itsthelore/lore-vscode`** repository, moved here with
its history preserved (ADR-092 convergence). The Marketplace / OpenVSX listing
identity and the published extension id are unchanged, so installed users are
unaffected — only the source repository moves. The extension consumes the
published `@itsthelore/rac-sdk` and the public `rac` CLI, never engine internals
(ADR-063).
