import {
  extractFeatures,
  extractFeatureVector,
  deriveRawPayload,
  FEATURE_NAMES,
  CanonicalRequest,
} from "../src/index";

const empty: Partial<CanonicalRequest> = {};

const sqli: Partial<CanonicalRequest> = {
  method: "GET",
  path: "/products",
  query: "id=1' OR '1'='1' UNION SELECT username,password FROM users--",
  userAgent: "Mozilla/5.0",
};

const xss: Partial<CanonicalRequest> = {
  method: "GET",
  path: "/search",
  query: "q=<script>alert(document.cookie)</script>",
  userAgent: "Mozilla/5.0",
};

const pathTraversal: Partial<CanonicalRequest> = {
  method: "GET",
  path: "/files",
  query: "file=../../../../etc/passwd",
  userAgent: "Mozilla/5.0",
};

const cmdi: Partial<CanonicalRequest> = {
  method: "POST",
  path: "/ping",
  body: "host=127.0.0.1; cat /etc/passwd",
  contentType: "application/x-www-form-urlencoded",
  userAgent: "Mozilla/5.0",
};

const legitimate: Partial<CanonicalRequest> = {
  method: "GET",
  path: "/api/users",
  query: "page=2&limit=10",
  userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
};

describe("FEATURE_NAMES", () => {
  it("tiene exactamente 73 columnas en el orden canonico", () => {
    expect(FEATURE_NAMES).toHaveLength(73);
    expect(FEATURE_NAMES[0]).toBe("payload_length");
    expect(FEATURE_NAMES[FEATURE_NAMES.length - 1]).toBe("endpoint_diversity_60s");
  });
});

describe("extractFeatures - forma del resultado", () => {
  it("devuelve exactamente las 73 claves de FEATURE_NAMES, todas numericas", () => {
    const features = extractFeatures(legitimate);
    expect(Object.keys(features)).toEqual([...FEATURE_NAMES]);
    for (const name of FEATURE_NAMES) {
      expect(Number.isFinite(features[name])).toBe(true);
    }
  });

  it("es determinista: la misma entrada produce el mismo vector", () => {
    const a = extractFeatureVector(sqli);
    const b = extractFeatureVector(sqli);
    expect(a).toEqual(b);
  });

  it("normaliza un CanonicalRequest vacio sin lanzar y produce features en cero", () => {
    const features = extractFeatures(empty);
    expect(features.payload_length).toBe(0);
    expect(features.sqli_keyword_count).toBe(0);
    expect(features.xss_marker_count).toBe(0);
    expect(features.traversal_sequence_count).toBe(0);
    expect(features.command_separator_count).toBe(0);
  });

  it("el grupo 9 (temporal) siempre es cero", () => {
    const features = extractFeatures(sqli);
    expect(features.req_count_1s).toBe(0);
    expect(features.req_count_5s).toBe(0);
    expect(features.req_count_60s).toBe(0);
    expect(features.error_rate_4xx_60s).toBe(0);
    expect(features.endpoint_diversity_60s).toBe(0);
  });
});

describe("deriveRawPayload", () => {
  it("prioriza body sobre query sobre path", () => {
    expect(deriveRawPayload({ body: "b", query: "q", path: "/p" } as CanonicalRequest)).toBe("b");
    expect(deriveRawPayload({ body: "", query: "q", path: "/p" } as CanonicalRequest)).toBe("q");
    expect(deriveRawPayload({ body: "", query: "", path: "/p" } as CanonicalRequest)).toBe("/p");
  });
});

describe("SQL Injection", () => {
  const features = extractFeatures(sqli);

  it("detecta keywords, UNION/SELECT y comentarios SQL", () => {
    expect(features.sqli_keyword_count).toBeGreaterThan(0);
    expect(features.union_present).toBe(1);
    expect(features.select_present).toBe(1);
    expect(features.sqli_comment_count).toBeGreaterThanOrEqual(1);
    expect(features.quote_count).toBeGreaterThan(0);
  });

  it("no dispara marcadores de XSS o command injection", () => {
    expect(features.script_tag_present).toBe(0);
    expect(features.os_path_indicator).toBe(0);
  });
});

describe("Cross-Site Scripting", () => {
  const features = extractFeatures(xss);

  it("detecta tags <script>, alert() y marcadores XSS", () => {
    expect(features.xss_marker_count).toBeGreaterThan(0);
    expect(features.script_tag_present).toBe(1);
    expect(features.alert_function_present).toBe(1);
    expect(features.html_tag_count).toBeGreaterThan(0);
  });

  it("no dispara marcadores de SQLi", () => {
    expect(features.union_present).toBe(0);
    expect(features.select_present).toBe(0);
  });
});

describe("Path Traversal / LFI", () => {
  const features = extractFeatures(pathTraversal);

  it("detecta secuencias de traversal y archivo sensible", () => {
    expect(features.traversal_sequence_count).toBeGreaterThan(0);
    expect(features.sensitive_file_target).toBe(1);
    expect(features.path_separator_count).toBeGreaterThan(0);
  });

  it("no dispara marcadores de XSS", () => {
    expect(features.xss_marker_count).toBe(0);
  });
});

describe("Command Injection", () => {
  const features = extractFeatures(cmdi);

  it("detecta separadores de comandos, comandos shell e indicador de path OS", () => {
    expect(features.command_separator_count).toBeGreaterThan(0);
    expect(features.shell_command_count).toBeGreaterThan(0);
    expect(features.os_path_indicator).toBe(1);
    expect(features.content_type_encoded).toBe(1);
  });

  it("usa el body como rawPayload (no la query)", () => {
    expect(features.body_length).toBe(cmdi.body!.length);
    expect(features.payload_length).toBe(cmdi.body!.length);
  });
});

describe("Trafico legitimo", () => {
  const features = extractFeatures(legitimate);

  it("no dispara ningun marcador de ataque", () => {
    expect(features.sqli_keyword_count).toBe(0);
    expect(features.union_present).toBe(0);
    expect(features.select_present).toBe(0);
    expect(features.xss_marker_count).toBe(0);
    expect(features.traversal_sequence_count).toBe(0);
    expect(features.command_separator_count).toBe(0);
    expect(features.shell_command_count).toBe(0);
  });

  it("calcula correctamente metodo y query params", () => {
    expect(features.method_is_get).toBe(1);
    expect(features.method_is_post).toBe(0);
    expect(features.query_param_count).toBe(2);
  });
});

describe("Grupo 8: HTTP request", () => {
  it("detecta user agents de scanners", () => {
    const features = extractFeatures({ ...legitimate, userAgent: "sqlmap/1.6" });
    expect(features.ua_suspicious).toBe(1);
  });

  it("calcula authorization_length desde extraHeaders", () => {
    const features = extractFeatures({
      ...legitimate,
      extraHeaders: { authorization: "Bearer abc123" },
    });
    expect(features.authorization_length).toBe("Bearer abc123".length);
  });

  it("cuenta headers no estandar en unusual_headers_count", () => {
    const features = extractFeatures({
      ...legitimate,
      extraHeaders: { "x-forwarded-for": "1.2.3.4", "x-custom-debug": "1" },
    });
    expect(features.unusual_headers_count).toBe(2);
  });

  it("status_code es 0 cuando no se provee (caso runtime)", () => {
    const features = extractFeatures(legitimate);
    expect(features.status_code).toBe(0);
  });

  it("status_code refleja el valor provisto (caso dataset de entrenamiento)", () => {
    const features = extractFeatures({ ...legitimate, statusCode: 403 });
    expect(features.status_code).toBe(403);
  });
});
