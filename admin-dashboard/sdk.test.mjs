/**
 * SDK Registry — unit tests
 * Run with: node --test sdk.test.mjs
 * Requires Node.js 18+, zero extra dependencies.
 */

import { readFileSync } from "node:fs";
import { strictEqual, deepStrictEqual, ok } from "node:assert";
import { describe, it } from "node:test";

// ── Pure logic (mirrors lib/sdk-registry.ts) ──────────────────────────────

function getRegistryUrl(sdk) {
  switch (sdk.registry) {
    case "npm":      return `https://www.npmjs.com/package/${sdk.packageName}`;
    case "pypi":     return `https://pypi.org/project/${sdk.packageName}/`;
    case "pkg.go.dev": return `https://pkg.go.dev/${sdk.packageName}`;
    default:         return "";
  }
}

function getLanguageColor(language) {
  const map = {
    TypeScript: "bg-blue-100 text-blue-700",
    Python:     "bg-yellow-100 text-yellow-700",
    Go:         "bg-cyan-100 text-cyan-700",
    React:      "bg-sky-100 text-sky-700",
    Vue:        "bg-emerald-100 text-emerald-700",
  };
  return map[language] ?? "bg-slate-100 text-slate-700";
}

// ── Load manifest ──────────────────────────────────────────────────────────

const manifest = JSON.parse(readFileSync("./public/sdk-registry.json", "utf-8"));
const sdks = manifest.sdks;

// ── Schema tests ───────────────────────────────────────────────────────────

describe("sdk-registry.json schema", () => {
  it("has exactly 5 SDKs (TypeScript, Python, Go, React, Vue)", () => {
    strictEqual(sdks.length, 5);
  });

  it("contains the required SDK languages", () => {
    const languages = sdks.map((s) => s.language);
    ok(languages.includes("TypeScript"), "missing TypeScript SDK");
    ok(languages.includes("Python"),     "missing Python SDK");
    ok(languages.includes("Go"),         "missing Go SDK");
    ok(languages.includes("React"),      "missing React SDK");
    ok(languages.includes("Vue"),        "missing Vue SDK");
  });

  it("every SDK has required string fields", () => {
    for (const sdk of sdks) {
      for (const field of ["id", "name", "language", "description", "installCommand",
                           "packageName", "docsUrl", "typeDocUrl", "repoUrl", "latestVersion"]) {
        ok(
          typeof sdk[field] === "string" && sdk[field].length > 0,
          `${sdk.id}: "${field}" must be a non-empty string`,
        );
      }
    }
  });

  it("every SDK registry value is one of the allowed registries", () => {
    const allowed = new Set(["npm", "pypi", "pkg.go.dev"]);
    for (const sdk of sdks) {
      ok(allowed.has(sdk.registry), `${sdk.id}: unknown registry "${sdk.registry}"`);
    }
  });

  it("every SDK has at least one version entry", () => {
    for (const sdk of sdks) {
      ok(Array.isArray(sdk.versions) && sdk.versions.length > 0,
        `${sdk.id}: must have at least one version`);
    }
  });

  it("latestVersion matches the first entry in versions array", () => {
    for (const sdk of sdks) {
      strictEqual(
        sdk.versions[0].version,
        sdk.latestVersion,
        `${sdk.id}: versions[0] should be the latest`,
      );
    }
  });

  it("every version entry has version, date, and non-empty changes array", () => {
    for (const sdk of sdks) {
      for (const v of sdk.versions) {
        ok(typeof v.version === "string" && v.version.length > 0,
          `${sdk.id}: version entry missing "version"`);
        ok(typeof v.date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v.date),
          `${sdk.id}@${v.version}: date must be YYYY-MM-DD`);
        ok(Array.isArray(v.changes) && v.changes.length > 0,
          `${sdk.id}@${v.version}: changes must be a non-empty array`);
      }
    }
  });

  it("all SDK ids are unique", () => {
    const ids = sdks.map((s) => s.id);
    strictEqual(new Set(ids).size, ids.length, "duplicate SDK ids found");
  });
});

// ── getRegistryUrl tests ──────────────────────────────────────────────────

describe("getRegistryUrl()", () => {
  it("builds correct npm URL", () => {
    const sdk = { registry: "npm", packageName: "fluid-client" };
    strictEqual(getRegistryUrl(sdk), "https://www.npmjs.com/package/fluid-client");
  });

  it("builds correct PyPI URL", () => {
    const sdk = { registry: "pypi", packageName: "fluid-py" };
    strictEqual(getRegistryUrl(sdk), "https://pypi.org/project/fluid-py/");
  });

  it("builds correct pkg.go.dev URL", () => {
    const sdk = { registry: "pkg.go.dev", packageName: "github.com/Stellar-Fluid/fluid-go" };
    strictEqual(getRegistryUrl(sdk), "https://pkg.go.dev/github.com/Stellar-Fluid/fluid-go");
  });

  it("returns correct URLs for all SDKs in the manifest", () => {
    for (const sdk of sdks) {
      const url = getRegistryUrl(sdk);
      ok(url.startsWith("https://"), `${sdk.id}: registry URL must start with https://`);
      ok(url.includes(sdk.packageName.split("/")[0]),
        `${sdk.id}: URL should contain part of the package name`);
    }
  });
});

// ── getLanguageColor tests ────────────────────────────────────────────────

describe("getLanguageColor()", () => {
  it("returns a non-empty class string for each SDK language", () => {
    const languages = ["TypeScript", "Python", "Go", "React", "Vue"];
    for (const lang of languages) {
      const result = getLanguageColor(lang);
      ok(typeof result === "string" && result.length > 0,
        `expected a class string for ${lang}`);
    }
  });

  it("returns distinct colours for different languages", () => {
    const colors = ["TypeScript", "Python", "Go", "React", "Vue"].map(getLanguageColor);
    const unique = new Set(colors);
    strictEqual(unique.size, 5, "each language should have a distinct color");
  });

  it("falls back for unknown language", () => {
    const result = getLanguageColor("COBOL");
    ok(result.includes("slate"), "unknown language should use slate fallback");
  });
});
