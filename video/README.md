# HeroCrypt Remotion Video

This folder contains a Remotion project that renders a short showcase video for HeroCrypt.

## Prereqs

- Node.js 18+
- npm

## Install

npm install

## Preview

npm run start

## Render

npm run render
npm run render:still

Output renders to `out/` (gitignored).

## Git tips

If you want to store rendered MP4s in Git, consider Git LFS:

git lfs install
git lfs track "*.mp4"

Alternatively, keep renders in `out/` and attach them as release artifacts.
