import { parseColor, THEME_PRESET_PALETTES, type ThemePresetPalette } from "@hermes/shared";
import type { DashboardTheme, ThemePalette, ThemeTypography, ThemeLayout } from "./types";

/**
 * Built-in dashboard themes.
 *
 * Each theme defines its own palette, typography, and layout so switching
 * themes produces visible changes beyond just color — fonts, density, and
 * corner-radius all shift to match the theme's personality.
 *
 * Theme names must stay in sync with the backend's
 * `_BUILTIN_DASHBOARD_THEMES` list in `hermes_cli/web_server.py`.
 *
 * Presets that also ship on the desktop (midnight, ember, mono, cyberpunk)
 * take their colours from `@hermes/shared` `THEME_PRESET_PALETTES` so both
 * surfaces render one palette; only typography/layout/overrides live here.
 */

// ---------------------------------------------------------------------------
// Shared typography / layout presets
// ---------------------------------------------------------------------------

/** Default system stack — neutral, safe fallback for every platform. */
const SYSTEM_SANS =
  'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
const SYSTEM_MONO =
  'ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace';

const DEFAULT_TYPOGRAPHY: ThemeTypography = {
  fontSans: SYSTEM_SANS,
  fontMono: SYSTEM_MONO,
  baseSize: "15px",
  lineHeight: "1.55",
  letterSpacing: "0",
};

const DEFAULT_LAYOUT: ThemeLayout = {
  radius: "0.5rem",
  density: "comfortable",
};

/**
 * Project a shared (desktop-shaped) preset palette onto the dashboard's
 * 3-slot model. The dashboard's `midground` is its text + primary-fill
 * colour, which is the desktop's `primary`; its `warmGlow` is the brand
 * accent stroke, which is the desktop's `midground` (falling back to `ring`).
 * `foreground` stays the dashboard's invisible white overlay. Dark palettes
 * are the dashboard's home turf, so a preset shipping `darkColors` is read
 * from that side.
 */
export function webPresetFromShared(
  preset: ThemePresetPalette,
): Omit<ThemePalette, "noiseOpacity"> {
  const colors = preset.darkColors ?? preset.colors;
  const [r, g, b] = parseColor(colors.midground ?? colors.ring) ?? [255, 255, 255];
  return {
    background: { hex: colors.background, alpha: 1 },
    midground: { hex: colors.primary, alpha: 1 },
    foreground: { hex: "#ffffff", alpha: 0 },
    warmGlow: `rgba(${r}, ${g}, ${b}, 0.3)`,
  };
}

// ---------------------------------------------------------------------------
// Themes
// ---------------------------------------------------------------------------

export const defaultTheme: DashboardTheme = {
  name: "default",
  label: "Hermes Teal",
  description: "Classic dark teal — the canonical Hermes look",
  palette: {
    background: { hex: "#041c1c", alpha: 1 },
    midground: { hex: "#ffe6cb", alpha: 1 },
    foreground: { hex: "#ffffff", alpha: 0 },
    warmGlow: "rgba(255, 189, 56, 0.35)",
    noiseOpacity: 1,
  },
  typography: DEFAULT_TYPOGRAPHY,
  layout: DEFAULT_LAYOUT,
  terminalBackground: "#000000",
};

export const midnightTheme: DashboardTheme = {
  name: "midnight",
  label: "Midnight",
  description: "Deep blue-violet with cool accents",
  palette: {
    ...webPresetFromShared(THEME_PRESET_PALETTES.midnight),
    noiseOpacity: 0.8,
  },
  typography: {
    ...DEFAULT_TYPOGRAPHY,
    fontSans: `"Inter", ${SYSTEM_SANS}`,
    fontMono: `"JetBrains Mono", ${SYSTEM_MONO}`,
    fontUrl:
      "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap",
    letterSpacing: "-0.005em",
  },
  layout: {
    ...DEFAULT_LAYOUT,
    radius: "0.75rem",
  },
};

export const emberTheme: DashboardTheme = {
  name: "ember",
  label: "Ember",
  description: "Warm crimson and bronze — forge vibes",
  palette: {
    ...webPresetFromShared(THEME_PRESET_PALETTES.ember),
    noiseOpacity: 1,
  },
  typography: {
    ...DEFAULT_TYPOGRAPHY,
    fontSans: `"Spectral", Georgia, "Times New Roman", serif`,
    fontMono: `"IBM Plex Mono", ${SYSTEM_MONO}`,
    fontUrl:
      "https://fonts.googleapis.com/css2?family=Spectral:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;700&display=swap",
  },
  layout: {
    ...DEFAULT_LAYOUT,
    radius: "0.25rem",
  },
  colorOverrides: {
    destructive: "#c92d0f",
    warning: "#f97316",
  },
};

export const monoTheme: DashboardTheme = {
  name: "mono",
  label: "Mono",
  description: "Clean grayscale — minimal and focused",
  palette: {
    ...webPresetFromShared(THEME_PRESET_PALETTES.mono),
    noiseOpacity: 0.6,
  },
  typography: {
    ...DEFAULT_TYPOGRAPHY,
    fontSans: `"IBM Plex Sans", ${SYSTEM_SANS}`,
    fontMono: `"IBM Plex Mono", ${SYSTEM_MONO}`,
    fontUrl:
      "https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap",
  },
  layout: {
    ...DEFAULT_LAYOUT,
    radius: "0",
  },
};

export const cyberpunkTheme: DashboardTheme = {
  name: "cyberpunk",
  label: "Cyberpunk",
  description: "Neon green on black — matrix terminal",
  palette: {
    ...webPresetFromShared(THEME_PRESET_PALETTES.cyberpunk),
    noiseOpacity: 1.2,
  },
  typography: {
    ...DEFAULT_TYPOGRAPHY,
    fontSans: `"Share Tech Mono", "JetBrains Mono", ${SYSTEM_MONO}`,
    fontMono: `"Share Tech Mono", "JetBrains Mono", ${SYSTEM_MONO}`,
    fontUrl:
      "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=JetBrains+Mono:wght@400;700&display=swap",
  },
  layout: {
    ...DEFAULT_LAYOUT,
    radius: "0",
  },
  colorOverrides: {
    success: "#00ff88",
    warning: "#ffd700",
    destructive: "#ff0055",
  },
};

export const roseTheme: DashboardTheme = {
  name: "rose",
  label: "Rosé",
  description: "Soft pink and warm ivory — easy on the eyes",
  palette: {
    background: { hex: "#1a0f15", alpha: 1 },
    midground: { hex: "#ffd4e1", alpha: 1 },
    foreground: { hex: "#ffffff", alpha: 0 },
    warmGlow: "rgba(249, 168, 212, 0.3)",
    noiseOpacity: 0.9,
  },
  typography: {
    ...DEFAULT_TYPOGRAPHY,
    fontSans: `"Fraunces", Georgia, serif`,
    fontMono: `"DM Mono", ${SYSTEM_MONO}`,
    fontUrl:
      "https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,600&family=DM+Mono:wght@400;500&display=swap",
  },
  layout: {
    ...DEFAULT_LAYOUT,
    radius: "1rem",
  },
};

/**
 * Quiet dark theme: a soft sage-slate canvas with muted, low-contrast text
 * that still clears WCAG AA, a single calm sage accent, system fonts, and no
 * grain, glow, scanline or border-image chrome. Dark rather than light so it
 * sits next to the other presets; the palette model has one variant per theme.
 */
export const calmTheme: DashboardTheme = {
  name: "calm",
  label: "Calm",
  description: "Soft sage-slate with muted text — quiet and easy on the eyes",
  palette: {
    background: { hex: "#232a28", alpha: 1 },
    midground: { hex: "#c9d1cb", alpha: 1 },
    foreground: { hex: "#ffffff", alpha: 0 },
    warmGlow: "rgba(150, 184, 165, 0.12)",
    noiseOpacity: 0,
  },
  typography: {
    ...DEFAULT_TYPOGRAPHY,
    lineHeight: "1.6",
  },
  layout: {
    ...DEFAULT_LAYOUT,
    radius: "0.625rem",
  },
  // Calm-only shell tuning. The stylesheet exists only while this theme is
  // active (applyCustomCSS removes it on switch), so none of this reaches the
  // other themes. The brand lockup is kept as is: it is the one element with
  // `leading-[0.95]`, which the type rules below leave out.
  customCSS: String.raw`
.grain::after { display: none; }

/* Solid primary buttons and the active tab: the sage accent, no bevel. */
html button.bg-midground,
html a.bg-midground {
  background-color: #96b8a5;
  color: #1b211f;
  box-shadow: none;
}

/* Outline buttons draw their border as an inset box-shadow in the text
   colour; keep it, but at about a third of the strength. */
html button.shadow-midground {
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--midground-base) 35%, transparent);
}

/* Sentence case and normal tracking across the shell. */
html .uppercase:not(.leading-\[0\.95\]),
html .text-display:not(.leading-\[0\.95\]) {
  text-transform: none;
}
html [class*="tracking-"]:not(.leading-\[0\.95\]),
html .text-display:not(.leading-\[0\.95\]) {
  letter-spacing: normal;
}

/* System font on buttons, badges, headings and inputs instead of the
   monospace and condensed display faces. Code and terminal keep theirs. */
html button.font-mono,
html .font-mondwest,
html .font-expanded,
html .font-compressed,
html .font-courier {
  font-family: var(--theme-font-sans);
}
html button.font-bold { font-weight: 500; }
html .font-expanded.font-bold { font-weight: 600; }

/* The shell hard-codes a bright green for success; use the calm one. */
html .text-success { color: #8fbf9f; }
html .bg-success { background-color: #8fbf9f; }
html .bg-success\/10 { background-color: color-mix(in srgb, #8fbf9f 10%, transparent); }
html .bg-success\/15 { background-color: color-mix(in srgb, #8fbf9f 15%, transparent); }
`,
  colorOverrides: {
    primary: "#96b8a5",
    primaryForeground: "#1b211f",
    ring: "#7f9d8d",
    success: "#8fbf9f",
    warning: "#d1b27e",
    destructive: "#d98a82",
    destructiveForeground: "#1b211f",
  },
  seriesColors: {
    inputTokenAccent: "#b3beb7",
    outputTokenAccent: "#96b8a5",
  },
  swatchColors: ["#232a28", "#c9d1cb", "#96b8a5"],
  terminalBackground: "#1d2321",
  terminalForeground: "#c9d1cb",
};

/** Light mode — vivid Nous-blue accents on a cream canvas. */
export const nousBlueTheme: DashboardTheme = {
  name: "nous-blue",
  label: "Nous Blue",
  description: "Light mode — vivid Nous-blue accents on cream canvas",
  palette: {
    background: { hex: "#E8F2FD", alpha: 1 },
    midground: { hex: "#0053FD", alpha: 1 },
    foreground: { hex: "#170d02", alpha: 0 },
    warmGlow: "rgba(0, 83, 253, 0.12)",
    noiseOpacity: 0,
  },
  typography: DEFAULT_TYPOGRAPHY,
  layout: DEFAULT_LAYOUT,
  terminalBackground: "#f5f8fc",
  terminalForeground: "#170d02",
  seriesColors: {
    inputTokenAccent: "#001934",
    outputTokenAccent: "#0053fd",
  },
  swatchColors: ["#170d02", "#0053FD", "#E8F2FD"],
};

/**
 * Same look as ``defaultTheme`` but with a larger root font size, looser
 * line-height, and ``spacious`` density so every rem-based size in the
 * dashboard scales up. For users who find the default 15px UI too dense.
 */
export const defaultLargeTheme: DashboardTheme = {
  name: "default-large",
  label: "Hermes Teal (Large)",
  description: "Hermes Teal with bigger fonts and roomier spacing",
  palette: defaultTheme.palette,
  typography: {
    ...DEFAULT_TYPOGRAPHY,
    baseSize: "18px",
    lineHeight: "1.65",
  },
  layout: {
    ...DEFAULT_LAYOUT,
    density: "spacious",
  },
};

export const BUILTIN_THEMES: Record<string, DashboardTheme> = {
  default: defaultTheme,
  "default-large": defaultLargeTheme,
  "nous-blue": nousBlueTheme,
  midnight: midnightTheme,
  ember: emberTheme,
  mono: monoTheme,
  cyberpunk: cyberpunkTheme,
  rose: roseTheme,
  calm: calmTheme,
};
