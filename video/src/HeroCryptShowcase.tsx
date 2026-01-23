import React from "react";
import {
  AbsoluteFill,
  Easing,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import {
  TransitionSeries,
  linearTiming,
  springTiming,
} from "@remotion/transitions";
import {fade} from "@remotion/transitions/fade";
import {slide} from "@remotion/transitions/slide";
import {BrandTag} from "./components/BrandTag";
import {SceneBackground} from "./components/SceneBackground";
import {theme} from "./theme";

type SceneProps = {
  durationInFrames: number;
};

type SceneDescriptor = {
  id: string;
  durationInSeconds: number;
  Component: React.FC<SceneProps>;
};

type SceneShellProps = {
  durationInFrames: number;
  align?: "center" | "left";
  children: React.ReactNode;
};

const TRANSITION_DURATION_IN_SECONDS = 0.6;

const toFrames = (seconds: number, fps: number) => Math.round(seconds * fps);

const useSpringIn = (
  frame: number,
  delayInSeconds = 0,
  durationInSeconds = 0.8
) => {
  const {fps} = useVideoConfig();
  return spring({
    frame: frame - delayInSeconds * fps,
    fps,
    durationInFrames: toFrames(durationInSeconds, fps),
    config: {
      damping: 200,
      mass: 0.9,
    },
  });
};

const getFadeInUpStyle = (
  frame: number,
  fps: number,
  delayInSeconds: number,
  distance = 18,
  durationInSeconds = 0.4
) => {
  const start = delayInSeconds * fps;
  const end = start + durationInSeconds * fps;
  const easing = Easing.out(Easing.quad);
  const opacity = interpolate(frame, [start, end], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing,
  });
  const translate = interpolate(frame, [start, end], [distance, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing,
  });
  return {
    opacity,
    transform: `translateY(${translate}px)`,
  };
};

const SceneShell: React.FC<SceneShellProps> = ({
  durationInFrames,
  align = "left",
  children,
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const easing = Easing.out(Easing.quad);
  const fadeInDuration = 0.45 * fps;
  const fadeOutDuration = 0.25 * fps;
  const fadeOutStart = Math.max(durationInFrames - fadeOutDuration, 0);
  const fadeIn = interpolate(frame, [0, fadeInDuration], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing,
  });
  const fadeOut = interpolate(frame, [fadeOutStart, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.in(Easing.quad),
  });
  const opacity = Math.min(fadeIn, fadeOut);
  const lift = interpolate(frame, [0, 0.6 * fps], [24, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing,
  });
  const scale = interpolate(frame, [0, 0.6 * fps], [0.98, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing,
  });
  const brandOpacity = interpolate(frame, [0, 0.35 * fps], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing,
  });
  const brandLift = interpolate(frame, [0, 0.35 * fps], [10, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing,
  });

  return (
    <AbsoluteFill
      style={{
        padding: 110,
        fontFamily: theme.fonts.body,
        color: theme.colors.ink,
      }}
    >
      <div style={{opacity: brandOpacity, transform: `translateY(${brandLift}px)`}}>
        <BrandTag />
      </div>
      <div
        style={{
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: align === "center" ? "center" : "flex-start",
        }}
      >
        <div
          style={{
            width: "100%",
            maxWidth: align === "center" ? 1200 : 1600,
            textAlign: align === "center" ? "center" : "left",
            opacity,
            transform: `translateY(${lift}px) scale(${scale})`,
          }}
        >
          {children}
        </div>
      </div>
    </AbsoluteFill>
  );
};

const Kicker: React.FC<{
  children: React.ReactNode;
  style?: React.CSSProperties;
}> = ({children, style}) => (
  <div
    style={{
      fontSize: 18,
      letterSpacing: 2.4,
      textTransform: "uppercase",
      fontWeight: 700,
      color: theme.colors.accentAlt,
      marginBottom: 18,
      ...style,
    }}
  >
    {children}
  </div>
);

const Title: React.FC<{
  children: React.ReactNode;
  size?: number;
  style?: React.CSSProperties;
}> = ({children, size = 64, style}) => (
  <div
    style={{
      fontSize: size,
      fontWeight: 700,
      letterSpacing: -1,
      marginBottom: 20,
      ...style,
    }}
  >
    {children}
  </div>
);

const Subtitle: React.FC<{
  children: React.ReactNode;
  maxWidth?: number;
  style?: React.CSSProperties;
}> = ({children, maxWidth = 680, style}) => (
  <div
    style={{
      fontSize: 26,
      lineHeight: 1.4,
      color: theme.colors.muted,
      maxWidth,
      ...style,
    }}
  >
    {children}
  </div>
);

const Chip: React.FC<{
  label: string;
  index: number;
}> = ({label, index}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const style = getFadeInUpStyle(frame, fps, 0.4 + index * 0.12, 12, 0.35);

  return (
    <div
      style={{
        padding: "10px 20px",
        borderRadius: 999,
        border: `1px solid ${theme.colors.accentAlt}`,
        background: theme.colors.panel,
        fontSize: 18,
        fontWeight: 600,
        color: theme.colors.ink,
        ...style,
      }}
    >
      {label}
    </div>
  );
};

const BulletRow: React.FC<{text: string}> = ({text}) => (
  <div style={{display: "flex", gap: 10, alignItems: "flex-start"}}>
    <div
      style={{
        width: 8,
        height: 8,
        marginTop: 8,
        borderRadius: 2,
        background: theme.colors.accent,
      }}
    />
    <div style={{fontSize: 20, color: theme.colors.muted}}>{text}</div>
  </div>
);

const FeatureCard: React.FC<{
  title: string;
  items: string[];
  index: number;
}> = ({title, items, index}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const style = getFadeInUpStyle(frame, fps, 0.35 + index * 0.15, 14, 0.45);

  return (
    <div
      style={{
        padding: "20px 22px",
        borderRadius: 20,
        background: theme.colors.panel,
        border: "1px solid rgba(27, 31, 36, 0.08)",
        boxShadow: "0 18px 40px rgba(18, 24, 32, 0.08)",
        ...style,
      }}
    >
      <div
        style={{
          fontSize: 22,
          fontWeight: 700,
          marginBottom: 12,
        }}
      >
        {title}
      </div>
      <div style={{display: "flex", flexDirection: "column", gap: 10}}>
        {items.map((item) => (
          <BulletRow key={item} text={item} />
        ))}
      </div>
    </div>
  );
};

const MetricCard: React.FC<{
  title: string;
  description: string;
  index: number;
}> = ({title, description, index}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const style = getFadeInUpStyle(frame, fps, 0.3 + index * 0.12, 12, 0.4);

  return (
    <div
      style={{
        padding: "24px 26px",
        borderRadius: 18,
        background: "rgba(255, 255, 255, 0.68)",
        border: "1px solid rgba(27, 31, 36, 0.08)",
        boxShadow: "0 16px 30px rgba(18, 24, 32, 0.08)",
        ...style,
      }}
    >
      <div
        style={{
          fontSize: 26,
          fontWeight: 700,
          marginBottom: 10,
        }}
      >
        {title}
      </div>
      <div style={{fontSize: 20, color: theme.colors.muted}}>{description}</div>
    </div>
  );
};

const CodeBlock: React.FC<{lines: string[]}> = ({lines}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const style = getFadeInUpStyle(frame, fps, 0.45, 14, 0.45);

  return (
    <div
      style={{
        background: theme.colors.darkPanel,
        borderRadius: 20,
        padding: "26px 30px",
        boxShadow: "0 24px 50px rgba(12, 16, 20, 0.28)",
        color: "#e6edf3",
        fontFamily: theme.fonts.code,
        fontSize: 22,
        lineHeight: 1.6,
        ...style,
      }}
    >
      {lines.map((line, index) => (
        <div key={`${line}-${index}`} style={{whiteSpace: "pre"}}>
          {line}
        </div>
      ))}
    </div>
  );
};

const IntroScene: React.FC<SceneProps> = ({durationInFrames}) => {
  const frame = useCurrentFrame();
  const titleIn = useSpringIn(frame, 0, 0.8);
  const subtitleIn = useSpringIn(frame, 0.2, 0.8);
  const chipsIn = useSpringIn(frame, 0.45, 0.8);
  const titleShift = interpolate(titleIn, [0, 1], [24, 0]);
  const subtitleShift = interpolate(subtitleIn, [0, 1], [18, 0]);
  const chipsShift = interpolate(chipsIn, [0, 1], [12, 0]);

  return (
    <SceneShell durationInFrames={durationInFrames} align="center">
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 22,
        }}
      >
        <div
          style={{
            fontSize: 96,
            fontWeight: 700,
            letterSpacing: -1,
            opacity: titleIn,
            transform: `translateY(${titleShift}px)`,
          }}
        >
          HeroCrypt
        </div>
        <div
          style={{
            fontSize: 36,
            fontWeight: 500,
            color: theme.colors.muted,
            opacity: subtitleIn,
            transform: `translateY(${subtitleShift}px)`,
          }}
        >
          RFC-compliant cryptography for .NET
        </div>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            justifyContent: "center",
            gap: 14,
            opacity: chipsIn,
            transform: `translateY(${chipsShift}px)`,
          }}
        >
          {["High performance", "Modern algorithms", "Multi-framework"].map(
            (label, index) => (
              <Chip key={label} label={label} index={index} />
            )
          )}
        </div>
      </div>
    </SceneShell>
  );
};

const CoreScene: React.FC<SceneProps> = ({durationInFrames}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const cards = [
    {
      title: "Password and KDFs",
      items: [
        "Argon2d/i/id (RFC 9106)",
        "Scrypt, PBKDF2",
        "HKDF, BIP32/39",
      ],
    },
    {
      title: "AEAD and stream",
      items: [
        "ChaCha20-Poly1305",
        "XChaCha20-Poly1305",
        "AES-GCM/CCM/SIV/OCB",
      ],
    },
    {
      title: "Public key and PGP",
      items: [
        "RSA PKCS#1 v2.2",
        "Ed25519 and X25519",
        "OpenPGP hybrid encryption",
      ],
    },
    {
      title: "Protocols",
      items: [
        "Noise, Signal, TLS 1.3",
        "OPAQUE PAKE",
        "Shamir secret sharing",
      ],
    },
  ];

  return (
    <SceneShell durationInFrames={durationInFrames}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1.05fr 1fr",
          gap: 60,
          alignItems: "center",
        }}
      >
        <div>
          <Kicker style={getFadeInUpStyle(frame, fps, 0.05, 8, 0.35)}>
            Core coverage
          </Kicker>
          <Title style={getFadeInUpStyle(frame, fps, 0.18, 12, 0.4)}>
            Algorithms you expect
          </Title>
          <Subtitle style={getFadeInUpStyle(frame, fps, 0.32, 12, 0.45)}>
            RFC-aligned implementations across hashing, AEAD, public key crypto,
            and protocol building blocks.
          </Subtitle>
        </div>
        <div style={{display: "grid", gap: 18}}>
          {cards.map((card, index) => (
            <FeatureCard
              key={card.title}
              title={card.title}
              items={card.items}
              index={index}
            />
          ))}
        </div>
      </div>
    </SceneShell>
  );
};

const PqcScene: React.FC<SceneProps> = ({durationInFrames}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const notes = [
    "FIPS 203, 204, 205 coverage",
    "Requires .NET 10+ with CNG or OpenSSL 3.5+",
    "Designed for harvest-now, decrypt-later defense",
  ];

  return (
    <SceneShell durationInFrames={durationInFrames}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 70,
          alignItems: "center",
        }}
      >
        <div>
          <Kicker style={getFadeInUpStyle(frame, fps, 0.05, 8, 0.35)}>
            Post-quantum
          </Kicker>
          <Title style={getFadeInUpStyle(frame, fps, 0.18, 12, 0.4)}>
            Ready for the next era
          </Title>
          <Subtitle
            maxWidth={640}
            style={getFadeInUpStyle(frame, fps, 0.32, 12, 0.45)}
          >
            Built-in ML-KEM, ML-DSA, and SLH-DSA implementations to stay ahead
            of quantum threats.
          </Subtitle>
        </div>
        <div
          style={{
            padding: "26px 28px",
            borderRadius: 22,
            background: "rgba(255, 255, 255, 0.72)",
            border: "1px solid rgba(27, 31, 36, 0.08)",
            boxShadow: "0 22px 40px rgba(18, 24, 32, 0.12)",
            display: "flex",
            flexDirection: "column",
            gap: 16,
            ...getFadeInUpStyle(frame, fps, 0.2, 14, 0.45),
          }}
        >
          <div
            style={{
              fontSize: 24,
              fontWeight: 700,
              color: theme.colors.accentAlt,
              letterSpacing: 1.2,
              textTransform: "uppercase",
            }}
          >
            ML-KEM / ML-DSA / SLH-DSA
          </div>
          <div style={{display: "flex", flexDirection: "column", gap: 12}}>
            {notes.map((note, index) => (
              <div
                key={note}
                style={{
                  display: "flex",
                  gap: 10,
                  alignItems: "flex-start",
                  ...getFadeInUpStyle(frame, fps, 0.35 + index * 0.12, 10, 0.35),
                }}
              >
                <div
                  style={{
                    width: 8,
                    height: 8,
                    marginTop: 8,
                    borderRadius: 2,
                    background: theme.colors.accent,
                  }}
                />
                <div style={{fontSize: 20, color: theme.colors.muted}}>{note}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </SceneShell>
  );
};

const PerformanceScene: React.FC<SceneProps> = ({durationInFrames}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const metrics = [
    {
      title: "SIMD acceleration",
      description: "AVX2, SSE2, NEON optimized paths",
    },
    {
      title: "Memory safety",
      description: "Zeroing, pools, constant-time compares",
    },
    {
      title: "Batch throughput",
      description: "3x to 10x gains on bulk operations",
    },
    {
      title: "Multi-framework",
      description: ".NET Standard 2.0 and .NET 8/9/10",
    },
  ];

  return (
    <SceneShell durationInFrames={durationInFrames}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1.1fr 1fr",
          gap: 60,
          alignItems: "center",
        }}
      >
        <div>
          <Kicker style={getFadeInUpStyle(frame, fps, 0.05, 8, 0.35)}>
            Performance
          </Kicker>
          <Title size={60} style={getFadeInUpStyle(frame, fps, 0.18, 12, 0.4)}>
            Built for speed and safety
          </Title>
          <Subtitle style={getFadeInUpStyle(frame, fps, 0.32, 12, 0.45)}>
            SIMD acceleration, memory-zeroed buffers, and careful API design
            deliver high throughput without compromising security.
          </Subtitle>
        </div>
        <div style={{display: "grid", gap: 18}}>
          {metrics.map((metric, index) => (
            <MetricCard
              key={metric.title}
              title={metric.title}
              description={metric.description}
              index={index}
            />
          ))}
        </div>
      </div>
    </SceneShell>
  );
};

const ApiScene: React.FC<SceneProps> = ({durationInFrames}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const bullets = [
    "Primitives: direct access to algorithms",
    "Operations: algorithm-agnostic facades",
    "Protocols: higher level constructions",
  ];
  const codeLines = [
    "using HeroCrypt;",
    "var key = RandomNumberGenerator.GetBytes(32);",
    "using var cipher = HeroCryptBuilder.ChaCha20Poly1305()",
    "    .WithKey(key)",
    "    .WithRandomNonce();",
    "",
    "var ciphertext = cipher.Encrypt(\"Hello, World!\"u8.ToArray());",
  ];

  return (
    <SceneShell durationInFrames={durationInFrames}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1.05fr",
          gap: 60,
          alignItems: "center",
        }}
      >
        <div>
          <Kicker style={getFadeInUpStyle(frame, fps, 0.05, 8, 0.35)}>
            Developer experience
          </Kicker>
          <Title size={60} style={getFadeInUpStyle(frame, fps, 0.18, 12, 0.4)}>
            Three layers of API
          </Title>
          <div style={{display: "flex", flexDirection: "column", gap: 14}}>
            {bullets.map((bullet, index) => (
              <div
                key={bullet}
                style={{
                  display: "flex",
                  gap: 10,
                  alignItems: "flex-start",
                  ...getFadeInUpStyle(frame, fps, 0.28 + index * 0.12, 10, 0.35),
                }}
              >
                <div
                  style={{
                    width: 8,
                    height: 8,
                    marginTop: 8,
                    borderRadius: 2,
                    background: theme.colors.accentAlt,
                  }}
                />
                <div style={{fontSize: 22, color: theme.colors.muted}}>
                  {bullet}
                </div>
              </div>
            ))}
          </div>
        </div>
        <CodeBlock lines={codeLines} />
      </div>
    </SceneShell>
  );
};

const ClosingScene: React.FC<SceneProps> = ({durationInFrames}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const badges = [
    ".NET Standard 2.0",
    ".NET 8/9/10",
    "MIT licensed",
    "NuGet: HeroCrypt",
  ];

  return (
    <SceneShell durationInFrames={durationInFrames} align="center">
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 20,
        }}
      >
        <Title style={getFadeInUpStyle(frame, fps, 0.08, 12, 0.4)}>
          Build with confidence
        </Title>
        <Subtitle
          maxWidth={760}
          style={getFadeInUpStyle(frame, fps, 0.22, 12, 0.45)}
        >
          HeroCrypt ships RFC-compliant cryptography with a production-ready API
          surface and multi-framework support.
        </Subtitle>
        <div
          style={{
            marginTop: 18,
            padding: "16px 28px",
            borderRadius: 16,
            background: theme.colors.darkPanel,
            color: "#e6edf3",
            fontFamily: theme.fonts.code,
            fontSize: 24,
            boxShadow: "0 22px 44px rgba(12, 16, 20, 0.28)",
            ...getFadeInUpStyle(frame, fps, 0.35, 10, 0.35),
          }}
        >
          dotnet add package HeroCrypt
        </div>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            justifyContent: "center",
            gap: 12,
            marginTop: 10,
          }}
        >
          {badges.map((badge, index) => (
            <div
              key={badge}
              style={{
                padding: "8px 16px",
                borderRadius: 999,
                border: `1px solid ${theme.colors.accentAlt}`,
                background: theme.colors.panel,
                fontSize: 18,
                fontWeight: 600,
                color: theme.colors.ink,
                ...getFadeInUpStyle(frame, fps, 0.45 + index * 0.12, 8, 0.3),
              }}
            >
              {badge}
            </div>
          ))}
        </div>
        <div style={{fontSize: 20, color: theme.colors.muted}}>
          github.com/KoalaFacts/HeroCrypt
        </div>
      </div>
    </SceneShell>
  );
};

const SCENES: SceneDescriptor[] = [
  {id: "intro", durationInSeconds: 4.5, Component: IntroScene},
  {id: "core", durationInSeconds: 6.5, Component: CoreScene},
  {id: "pqc", durationInSeconds: 6.0, Component: PqcScene},
  {id: "performance", durationInSeconds: 6.0, Component: PerformanceScene},
  {id: "api", durationInSeconds: 7.0, Component: ApiScene},
  {id: "closing", durationInSeconds: 4.5, Component: ClosingScene},
];

const getSceneTimings = (fps: number) =>
  SCENES.map((scene) => ({
    ...scene,
    durationInFrames: toFrames(scene.durationInSeconds, fps),
  }));

const getTransitionSpecs = (fps: number) => {
  const durationInFrames = toFrames(TRANSITION_DURATION_IN_SECONDS, fps);
  const slideTiming = springTiming({
    config: {damping: 200},
    durationInFrames,
  });
  const fadeTiming = linearTiming({durationInFrames});

  return [
    {presentation: slide({direction: "from-right"}), timing: slideTiming},
    {presentation: fade(), timing: fadeTiming},
    {presentation: slide({direction: "from-bottom"}), timing: slideTiming},
    {presentation: fade(), timing: fadeTiming},
    {presentation: slide({direction: "from-left"}), timing: slideTiming},
  ];
};

export const getShowcaseDurationInFrames = (fps: number) => {
  const scenes = getSceneTimings(fps);
  const transitionFrames = toFrames(TRANSITION_DURATION_IN_SECONDS, fps);
  const transitionsTotal = transitionFrames * Math.max(scenes.length - 1, 0);
  const scenesTotal = scenes.reduce(
    (total, scene) => total + scene.durationInFrames,
    0
  );
  return scenesTotal - transitionsTotal;
};

export const HeroCryptShowcase: React.FC = () => {
  const {fps} = useVideoConfig();
  const sceneTimings = getSceneTimings(fps);
  const transitions = getTransitionSpecs(fps);

  return (
    <AbsoluteFill style={{fontFamily: theme.fonts.body, color: theme.colors.ink}}>
      <SceneBackground />
      <TransitionSeries>
        {sceneTimings.map((scene, index) => {
          const SceneComponent = scene.Component;
          return (
            <React.Fragment key={scene.id}>
              <TransitionSeries.Sequence durationInFrames={scene.durationInFrames}>
                <SceneComponent durationInFrames={scene.durationInFrames} />
              </TransitionSeries.Sequence>
              {index < transitions.length ? (
                <TransitionSeries.Transition
                  presentation={transitions[index].presentation}
                  timing={transitions[index].timing}
                />
              ) : null}
            </React.Fragment>
          );
        })}
      </TransitionSeries>
    </AbsoluteFill>
  );
};
