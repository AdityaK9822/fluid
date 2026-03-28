export interface SdkVersion {
  version: string;
  date: string;
  changes: string[];
}

export interface Sdk {
  id: string;
  name: string;
  language: string;
  description: string;
  installCommand: string;
  registry: "npm" | "pypi" | "pkg.go.dev";
  packageName: string;
  docsUrl: string;
  typeDocUrl: string;
  repoUrl: string;
  latestVersion: string;
  versions: SdkVersion[];
}

export interface SdkRegistryManifest {
  sdks: Sdk[];
}

import registryData from "../public/sdk-registry.json";

/** Load SDKs from the static registry manifest. */
export function loadSdkRegistry(): Sdk[] {
  return (registryData as SdkRegistryManifest).sdks;
}

/** Build the registry URL for a given SDK package. */
export function getRegistryUrl(sdk: Sdk): string {
  switch (sdk.registry) {
    case "npm":
      return `https://www.npmjs.com/package/${sdk.packageName}`;
    case "pypi":
      return `https://pypi.org/project/${sdk.packageName}/`;
    case "pkg.go.dev":
      return `https://pkg.go.dev/${sdk.packageName}`;
  }
}

/** Language colour used for the badge. */
export function getLanguageColor(language: string): string {
  const map: Record<string, string> = {
    TypeScript: "bg-blue-100 text-blue-700",
    Python: "bg-yellow-100 text-yellow-700",
    Go: "bg-cyan-100 text-cyan-700",
    React: "bg-sky-100 text-sky-700",
    Vue: "bg-emerald-100 text-emerald-700",
  };
  return map[language] ?? "bg-slate-100 text-slate-700";
}
