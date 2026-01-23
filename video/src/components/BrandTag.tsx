import React from "react";
import {theme} from "../theme";

export const BrandTag: React.FC = () => {
  return (
    <div
      style={{
        position: "absolute",
        top: 56,
        left: 110,
        display: "flex",
        alignItems: "center",
        gap: 10,
        fontSize: 18,
        letterSpacing: 2.4,
        textTransform: "uppercase",
        fontWeight: 700,
        color: theme.colors.accentAlt,
      }}
    >
      <div
        style={{
          width: 12,
          height: 12,
          borderRadius: 3,
          background: theme.colors.accent,
        }}
      />
      HeroCrypt
    </div>
  );
};
