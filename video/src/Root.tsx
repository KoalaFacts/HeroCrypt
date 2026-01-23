import React from "react";
import {Composition} from "remotion";
import {HeroCryptShowcase, getShowcaseDurationInFrames} from "./HeroCryptShowcase";
import {HeroCryptCover} from "./HeroCryptCover";

export const Root: React.FC = () => {
  const fps = 30;
  const showcaseDuration = getShowcaseDurationInFrames(fps);

  return (
    <>
      <Composition
        id="HeroCryptShowcase"
        component={HeroCryptShowcase}
        durationInFrames={showcaseDuration}
        fps={fps}
        width={1920}
        height={1080}
      />
      <Composition
        id="HeroCryptCover"
        component={HeroCryptCover}
        durationInFrames={1}
        fps={fps}
        width={1920}
        height={1080}
      />
    </>
  );
};
