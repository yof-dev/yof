/**
 * End-of-life base images, from a table kept in this file (no image is pulled, no registry is asked).
 *
 * A date is a day where the project names one and a month (2026-10) where it names only the month. For Debian the
 * date is the end of LTS, for Ubuntu the end of standard support (paid extended support is not counted).
 *
 * THE TABLE IS DATED: BASE_IMAGE_TABLE_DATE below is the day it was last checked against each project's own
 * end-of-life page, and every finding prints that date. A tag that is not in the table is not judged. When a release
 * line reaches its end of life after that date, yof does not know until the table is updated: review it at least
 * every three months (the test yof-rules2-containers pins that the date is not in the future).
 * Sources: nodejs.org/en/about/previous-releases, devguide.python.org/versions, alpinelinux.org/releases,
 * wiki.debian.org/LTS, ubuntu.com/about/release-cycle, nginx.org (only the current stable and mainline lines are
 * maintained).
 *
 * WHAT THIS IS NOT: yof does not scan built images or the operating-system packages inside them. A tag that is still
 * maintained can hold packages with known vulnerabilities, and this table says nothing about that.
 */
export const BASE_IMAGE_TABLE_DATE = "2026-11-12";

export interface EolEntry { line: string; eol: string }

/** Official images only (docker.io/library/<name>), by release line -> the day its maintenance ended. */
export const BASE_IMAGE_EOL: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  node: {
    "4": "2018-04-30", "5": "2016-06-30", "6": "2019-04-30", "7": "2017-06-30", "8": "2019-12-31", "9": "2018-06-30", "10": "2021-04-30", "11": "2019-06-01",
    "12": "2022-04-30", "13": "2020-06-01", "14": "2023-04-30", "15": "2021-06-01", "16": "2023-09-11", "17": "2022-06-01", "18": "2025-04-30",
    "19": "2023-06-01", "20": "2026-04-30", "21": "2024-06-01", "23": "2025-06-01", "25": "2026-06-01",
  },
  python: {
    "2": "2020-01-01", "2.7": "2020-01-01", "3.0": "2009-06-27", "3.1": "2012-04-09", "3.2": "2016-02-20", "3.3": "2017-09-29", "3.4": "2019-03-18",
    "3.5": "2020-09", "3.6": "2021-12-23", "3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10", "3.10": "2026-10",
  },
  alpine: {
    "3.8": "2020-05-01", "3.9": "2020-11-01", "3.10": "2021-05-01", "3.11": "2021-11-01", "3.12": "2022-05-01", "3.13": "2022-11-01", "3.14": "2023-05-01",
    "3.15": "2023-11-01", "3.16": "2024-05-23", "3.17": "2024-11-22", "3.18": "2025-05-09", "3.19": "2025-11-01", "3.20": "2026-04-01", "3.21": "2026-11-01",
  },
  debian: {
    "8": "2020-06-30", jessie: "2020-06-30", "9": "2022-06-30", stretch: "2022-06-30", "10": "2024-06-30", buster: "2024-06-30", "11": "2026-08-31", bullseye: "2026-08-31",
  },
  ubuntu: {
    "14.04": "2019-04-25", trusty: "2019-04-25", "16.04": "2021-04-30", xenial: "2021-04-30", "18.04": "2023-05-31", bionic: "2023-05-31", "20.04": "2025-05-31", focal: "2025-05-31",
    "21.04": "2022-01-20", hirsute: "2022-01-20", "21.10": "2022-07-14", impish: "2022-07-14", "22.10": "2023-07-20", kinetic: "2023-07-20", "23.04": "2024-01-25", lunar: "2024-01-25",
    "23.10": "2024-07-11", mantic: "2024-07-11", "24.10": "2025-07-10", oracular: "2025-07-10", "25.04": "2026-01", plucky: "2026-01",
  },
  nginx: {
    "1.10": "2017-04-12", "1.12": "2018-04-17", "1.14": "2019-04-23", "1.16": "2020-04-21", "1.18": "2021-04-20", "1.19": "2021-04-20", "1.20": "2022-05-24", "1.21": "2022-05-24",
    "1.22": "2023-04-11", "1.23": "2023-04-11", "1.24": "2024-04-23", "1.25": "2024-04-23", "1.26": "2025-04-23", "1.27": "2025-04-23",
  },
};

/** Debian and Alpine releases named in the tag of another official image (node:22-buster, python:3.12-alpine3.16). */
const OS_SUFFIX: readonly [RegExp, string, (m: RegExpExecArray) => string][] = [
  [/(?:^|-)(jessie|stretch|buster|bullseye)(?:-|$)/, "debian", (m) => m[1]!],
  [/(?:^|-)alpine(3\.\d+)(?:\.\d+)?(?:-|$)/, "alpine", (m) => m[1]!],
];

export interface EolHit { image: string; line: string; eol: string; part: "image" | "os" }

/** The end-of-life release lines an image reference names, or [] (not an official image, not in the table, a digest only). */
export function eolOf(ref: string): EolHit[] {
  const noDigest = ref.split("@")[0]!;
  const slash = noDigest.lastIndexOf("/");
  const colon = noDigest.lastIndexOf(":");
  if (colon <= slash) return [];
  const path = noDigest.slice(0, colon).toLowerCase();
  const tag = noDigest.slice(colon + 1).toLowerCase();
  const name = path.replace(/^(?:(?:index\.)?docker\.io\/)?(?:library\/)?/, "");
  const table = BASE_IMAGE_EOL[name];
  if (!table || name.includes("/")) return [];
  const out: EolHit[] = [];
  const v = /^v?(\d+(?:\.\d+)*)/.exec(tag)?.[1];
  if (v) {
    const parts = v.split(".");
    // the release line is the major for node, major.minor for the others; "3" alone (python:3) follows the newest 3.x
    const line = name === "node" ? parts[0]! : parts.length >= 2 ? `${parts[0]}.${parts[1]}` : name === "debian" ? parts[0]! : name === "python" && parts[0] === "2" ? "2" : "";
    if (line && table[line]) out.push({ image: name, line, eol: table[line]!, part: "image" });
  } else {
    const word = /^([a-z]+)/.exec(tag)?.[1] ?? "";
    if (word && table[word]) out.push({ image: name, line: word, eol: table[word]!, part: "image" });
  }
  if (name !== "debian" && name !== "alpine") {
    for (const [re, os, pick] of OS_SUFFIX) {
      const m = re.exec(tag);
      const line = m ? pick(m) : "";
      const eol = line ? BASE_IMAGE_EOL[os]?.[line] : undefined;
      if (eol) out.push({ image: os, line, eol, part: "os" });
    }
  }
  return out;
}
