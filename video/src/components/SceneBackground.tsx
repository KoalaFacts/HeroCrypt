import React from "react";
import {
  AbsoluteFill,
  interpolate,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import {gradients, theme} from "../theme";

export const SceneBackground: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const t = frame / fps;
  const drift = Math.sin(t * 0.45) * 24;
  const driftAlt = Math.cos(t * 0.35) * 18;
  const glow = interpolate(Math.sin(t * 0.6), [-1, 1], [0.14, 0.22]);
  const glowAlt = interpolate(Math.cos(t * 0.5), [-1, 1], [0.12, 0.2]);
  const scale = interpolate(Math.sin(t * 0.4), [-1, 1], [0.98, 1.03]);
  const scaleAlt = interpolate(Math.cos(t * 0.35), [-1, 1], [0.97, 1.02]);
  const gridOpacity = interpolate(Math.sin(t * 0.3), [-1, 1], [0.38, 0.56]);

  return (
    <AbsoluteFill style={{background: gradients.backdrop}}>
      <div
        style={{
          position: "absolute",
          width: 720,
          height: 720,
          borderRadius: 999,
          background: theme.colors.accent,
          opacity: glow,
          top: -240,
          right: -180,
          filter: "blur(6px)",
          transform: `translate3d(${drift}px, ${-driftAlt}px, 0) scale(${scale})`,
        }}
      />
      <div
        style={{
          position: "absolute",
          width: 640,
          height: 640,
          borderRadius: 999,
          background: theme.colors.accentAlt,
          opacity: glowAlt,
          bottom: -220,
          left: -200,
          filter: "blur(6px)",
          transform: `translate3d(${driftAlt}px, ${drift}px, 0) scale(${scaleAlt})`,
        }}
      />
      <div
        style={{
          position: "absolute",
          inset: 0,
          backgroundImage:
            "radial-gradient(rgba(27, 31, 36, 0.08) 1px, transparent 1px)",
          backgroundSize: "26px 26px",
          opacity: gridOpacity,
        }}
      />
    </AbsoluteFill>
  );
};
