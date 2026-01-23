import React from "react";
import {AbsoluteFill} from "remotion";
import {BrandTag} from "./components/BrandTag";
import {SceneBackground} from "./components/SceneBackground";
import {theme} from "./theme";

export const HeroCryptCover: React.FC = () => {
  return (
    <AbsoluteFill style={{fontFamily: theme.fonts.display, color: theme.colors.ink}}>
      <SceneBackground />
      <BrandTag />
      <div
        style={{
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 110,
        }}
      >
        <div style={{textAlign: "center", maxWidth: 1200}}>
          <div
            style={{
              fontSize: 96,
              fontWeight: 700,
              letterSpacing: -1,
              marginBottom: 24,
            }}
          >
            HeroCrypt
          </div>
          <div
            style={{
              fontSize: 34,
              fontWeight: 500,
              color: theme.colors.muted,
              marginBottom: 30,
            }}
          >
            RFC-compliant cryptography for .NET
          </div>
          <div
            style={{
              display: "inline-flex",
              gap: 14,
              flexWrap: "wrap",
              justifyContent: "center",
            }}
          >
            {[
              "High performance",
              "Modern algorithms",
              "Multi-framework",
            ].map((label) => (
              <div
                key={label}
                style={{
                  padding: "10px 20px",
                  borderRadius: 999,
                  border: `1px solid ${theme.colors.accentAlt}`,
                  background: theme.colors.panel,
                  fontSize: 18,
                  fontWeight: 600,
                  color: theme.colors.ink,
                }}
              >
                {label}
              </div>
            ))}
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};
