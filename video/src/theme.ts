export const theme = {
  colors: {
    backgroundStart: "#f7f2e7",
    backgroundEnd: "#e6eef6",
    ink: "#1b1f24",
    muted: "#4b5563",
    accent: "#e05d3b",
    accentAlt: "#2a6f97",
    panel: "rgba(255, 255, 255, 0.82)",
    darkPanel: "rgba(15, 18, 22, 0.92)",
  },
  fonts: {
    display: '"Space Grotesk", sans-serif',
    body: '"Space Grotesk", sans-serif',
    code: '"IBM Plex Mono", monospace',
  },
} as const;

export const gradients = {
  backdrop: `linear-gradient(135deg, ${theme.colors.backgroundStart} 0%, ${theme.colors.backgroundEnd} 100%)`,
} as const;
