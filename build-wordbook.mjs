// 영단어장 배포 파일 생성
//
// 원본 wordbook.html 은 Claude 아티팩트용이라 <head> 가 없다.
// 아티팩트로 열 때는 Claude 가 head 를 붙여 주지만, Render 에서 생파일로
// 서빙하면 viewport 메타가 없어 휴대폰이 화면 폭을 980px 로 가정하고
// 전체를 축소해 버린다. 그래서 배포본에만 head 를 씌운다.
//
// 실행:  node build-wordbook.mjs

import fs from "node:fs";
import path from "node:path";

const SRC = path.join("..", "wordbook.html");
const OUT = path.join("site", "index.html");

const body = fs.readFileSync(SRC, "utf8");

// 홈 화면 아이콘용 초록 책 이모지
const favicon =
  "data:image/svg+xml," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">' +
      '<text y="0.9em" font-size="90">\u{1F4D7}</text></svg>'
  );

const head = `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<meta name="description" content="생활·업무 영단어 8000개 학습">
<meta name="theme-color" content="#F2F5F4" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0E1918" media="(prefers-color-scheme: dark)">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="영단어">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<link rel="icon" href="${favicon}">
<style>:root{color-scheme:light dark}html{-webkit-text-size-adjust:100%}</style>
</head>
<body>
`;

const tail = `
</body>
</html>
`;

fs.mkdirSync("site", { recursive: true });
fs.writeFileSync(OUT, head + body + tail, "utf8");

// 한글은 UTF-8 에서 3바이트라 문자열 length 로 재면 실제보다 작게 나온다
const bytes = fs.statSync(OUT).size;
const words = (body.match(/const W=\[[\s\S]*?\n\];/) || [""])[0].split("\n").length - 2;
console.log(`${OUT} 생성 — ${bytes.toLocaleString()}바이트, 단어 ${words.toLocaleString()}개`);
