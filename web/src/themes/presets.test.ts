import { contrastRatio, THEME_PRESET_PALETTES, type ThemePresetPalette } from "@hermes/shared";
import { describe, expect, it } from "vitest";

import { BUILTIN_THEMES, webPresetFromShared } from "./presets";

// Every preset the dashboard shares with the desktop must render the shared
// table's palette, not a private copy — that is the whole point of the table.
// The second assertion keeps the projection honest: whatever slot the mapping
// picks as the dashboard's text/primary colour has to stay legible on the
// canvas it picks, so a future re-mapping cannot silently ship grey-on-grey.
describe("dashboard presets derive from the shared palette table", () => {
  const shared = Object.keys(BUILTIN_THEMES).filter(
    (name): name is keyof typeof THEME_PRESET_PALETTES => name in THEME_PRESET_PALETTES,
  );

  it("covers the presets both surfaces ship", () => {
    expect(shared).toEqual(expect.arrayContaining(["cyberpunk", "ember", "midnight", "mono"]));
  });

  it.each(shared)("%s: canvas equals the shared background and the accent reads on it", (name) => {
    const preset: ThemePresetPalette = THEME_PRESET_PALETTES[name];
    const derived = webPresetFromShared(preset);
    const palette = BUILTIN_THEMES[name].palette;

    expect(palette.background.hex).toBe((preset.darkColors ?? preset.colors).background);
    expect(palette.midground.hex).toBe(derived.midground.hex);
    expect(contrastRatio(palette.midground.hex, palette.background.hex)).toBeGreaterThanOrEqual(3);
  });
});

// The calm preset is the quiet one: muted, but body text and the accent
// still have to clear WCAG AA against the canvas, and it must not carry any
// of the loud chrome the other presets use.
describe("calm preset", () => {
  const calm = BUILTIN_THEMES.calm;

  it("is registered and leaves the default theme alone", () => {
    expect(calm.name).toBe("calm");
    expect(BUILTIN_THEMES.default.name).toBe("default");
  });

  it("keeps body text and the accent at AA contrast on the canvas", () => {
    const bg = calm.palette.background.hex;
    expect(contrastRatio(calm.palette.midground.hex, bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(calm.colorOverrides?.primary ?? "", bg)).toBeGreaterThanOrEqual(4.5);
    expect(
      contrastRatio(calm.colorOverrides?.primaryForeground ?? "", calm.colorOverrides?.primary ?? ""),
    ).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(calm.colorOverrides?.destructive ?? "", bg)).toBeGreaterThanOrEqual(4.5);
  });

  it("uses a soft canvas, no grain and no border-image or glow chrome", () => {
    expect(calm.palette.background.hex).not.toMatch(/^#(000000|ffffff)$/i);
    expect(calm.palette.noiseOpacity).toBe(0);
    expect(calm.componentStyles).toBeUndefined();
    expect(calm.assets).toBeUndefined();
    expect(calm.customCSS ?? "").not.toMatch(/border-image|animation|scanline|glow|text-shadow|blur/i);
  });
});

describe("calm preset stylesheet", () => {
  const css = BUILTIN_THEMES.calm.customCSS ?? "";

  it("keeps the CSS escapes intact so the selectors can match", () => {
    expect(css).toContain("leading-\\[0\\.95\\]");
    expect(css).toContain(".bg-success\\/10");
  });

  it("does not touch the brand lockup", () => {
    for (const rule of css.match(/[^{}]*(?:uppercase|tracking-)[^{}]*\{/g) ?? []) {
      expect(rule).toContain("leading-\\[0\\.95\\]");
    }
  });
});
