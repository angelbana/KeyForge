export const themes = [
  { id: "obsidian", name: "Obsidian Monolith" },
  { id: "tokyo", name: "Tokyo Night Terminal" },
  { id: "paper", name: "Paper & Ink" },
  { id: "solarized", name: "Solarized Machining" },
] as const;
export type Theme = (typeof themes)[number]["id"];
export function readTheme(): Theme {
  try {
    const saved = localStorage.getItem("keyforge.theme");
    return themes.find((theme) => theme.id === saved)?.id || "obsidian";
  } catch {
    return "obsidian";
  }
}
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem("keyforge.theme", theme);
  } catch {
    /* Preference storage is optional. */
  }
}
export function fingerprintPairs(fingerprint: string): string[] {
  return fingerprint.replace(/^SHA256:/, "").match(/.{1,2}/g) || [];
}
export function passphraseLevel(value: string): number {
  return value.length >= 20
    ? 4
    : value.length >= 16
      ? 3
      : value.length >= 12
        ? 2
        : value.length
          ? 1
          : 0;
}
// Apply a saved theme before React's first render, avoiding a light first frame.
if (typeof document !== "undefined") applyTheme(readTheme());
