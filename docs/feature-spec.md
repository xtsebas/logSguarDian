# Especificación del vector de features

- **Total features extraídas:** 72
- **Features usadas por el modelo:** 66
- **Grupos:** A (semánticas de ataque), B (estructura HTTP), C (URL/path), D (parámetros/body), E (evasión por encoding)
- **Fuente canónica:** `packages/extractor/src/index.ts` (R1 — única implementación)
- **rawPayload:** campo sobre el que operan los grupos A–E (excepto métricas específicas de uri/body). Derivado en `deriveRawPayload()`: `body` si `body ≠ ""`, si no `query`, si no `path`.

---

## Tabla de features (72 filas)

> **Convención de grupos:**
> A = semántica de ataque (SQLi/XSS/Path Traversal/CMDi) · B = estructura HTTP · C = URL/path · D = composición de payload/body · E = evasión por encoding/caracteres
>
> **Riesgo de leakage:** "Sí" cuando la feature podría codificar información correlacionada con la etiqueta por razones ajenas al patrón de ataque (e.g., artefacto de formato de un dataset fuente).

| # | Nombre | Grupo | Fórmula/Descripción | Categoría de ataque | Costo computacional | Riesgo de leakage |
|---|--------|-------|---------------------|---------------------|--------------------|--------------------|
| 1 | `payload_length` | D | Longitud en caracteres UTF-16 de rawPayload: `rawPayload.length` | General | O(1) | No — longitud de contenido, independiente del origen |
| 2 | `payload_entropy` | D | Entropía de Shannon sobre los **bytes UTF-8** de rawPayload: H = −Σ p(b)·log₂(p(b) + 1×10⁻¹²) para cada byte b distinto. Implementado en `shannonEntropy()` | General | O(n) — un recorrido sobre bytes | No |
| 3 | `uri_length` | C | Longitud de la URI completa: `(query ≠ "" ? path + "?" + query : path).length` | General | O(1) | No |
| 4 | `path_length` | C | Longitud del path sin query string: `uri.replace(/\?.*$/, "").length` | General | O(n) — regex de corte | No |
| 5 | `query_string_length` | C | Longitud del query string sin el "?" inicial: `query.length` | General | O(1) | No |
| 6 | `body_length` | D | Longitud del body UTF-8: `body.length` | General | O(1) | No |
| 7 | `body_entropy` | D | Entropía de Shannon (misma fórmula que #2) sobre bytes UTF-8 de `body` | General | O(n) | No |
| 8 | `path_depth` | C | Número de ocurrencias de "/" en el path (sin query string): `countMatches(pathOnly, /\//g)`. Un path `/a/b/c` produce 3 | General | O(n) | No |
| 9 | `query_param_count` | C | Número de parámetros en el query string: `countMatches(query, /&/g) + (query.length > 0 ? 1 : 0)` | General | O(n) | No |
| 10 | `fragment_present` | C | Indicador binario: 1 si la URI contiene "#", 0 si no: `uri.includes("#") ? 1 : 0` | General | O(n) | No |
| 11 | `special_char_ratio` | D | Proporción de caracteres especiales: `countMatches(payload, /[!@#$%^&*()\[\]{};:'",./<>?\|\\=+_~\`]/g) / max(payload.length, 1)` | General | O(n) | No |
| 12 | `numeric_char_ratio` | D | Proporción de dígitos: `countMatches(payload, /\d/g) / max(payload.length, 1)` | General | O(n) | No |
| 13 | `uppercase_ratio` | D | Proporción de letras mayúsculas: `countMatches(payload, /[A-Z]/g) / max(payload.length, 1)` | General | O(n) | No |
| 14 | `whitespace_count` | D | Número de caracteres de espacio en blanco (space, tab, newline, etc.): `countMatches(payload, /\s/g)` | General | O(n) | No |
| 15 | `newline_char_count` | E | Número de saltos de línea literales más sus variantes URL-encoded: `countMatches(payload, /[\n\r]/g) + countMatches(payload, /%0[da]/gi)` | General / CMDi | O(n) | No |
| 16 | `null_byte_count` | E | Número de bytes nulos literales (`\x00`) más su forma URL-encoded (`%00`): `countMatches(payload, /\x00/g) + countMatches(payload, /%00/gi)` | General / Evasión | O(n) | No |
| 17 | `extended_ascii_ratio` | E | Proporción de code points > 127: itera con `for...of` (code points Unicode), cuenta los que superan 127, divide por `s.length` (unidades UTF-16). Implementado en `extendedAsciiRatio()` | General / Evasión | O(n) | No |
| 18 | `payload_token_count` | D | Número de tokens separados por espacios: `payload.trim().split(/\s+/).length` si no vacío, 0 si vacío. Implementado en `tokenCount()` | General | O(n) | No |
| 19 | `url_encoded_ratio` | E | Proporción de secuencias URL-encoded: `countMatches(payload, /%[0-9a-fA-F]{2}/g) / max(payload.length, 1)` | Evasión / General | O(n) | No |
| 20 | `encoded_char_freq` | E | Conteo absoluto de secuencias URL-encoded (mismo numerador que #19, sin normalizar): `countMatches(payload, /%[0-9a-fA-F]{2}/g)` | Evasión / General | O(n) | No |
| 21 | `double_encoded_count` | E | Número de secuencias doblemente URL-encoded (el "%" está codificado como "%25"): `countMatches(payload, /%25[0-9a-fA-F]{2}/gi)` | Evasión | O(n) | No |
| 22 | `hex_escape_count` | E | Número de escapes hexadecimales de estilo C/JS (`\xNN`) o literales hexadecimales (`0xNNN...`): `countMatches(payload, /(\\x[0-9a-fA-F]{2}\|0x[0-9a-fA-F]+)/gi)` | Evasión | O(n) | No |
| 23 | `unicode_escape_count` | E | Número de escapes Unicode en variantes `\uNNNN`, `\UNNNNNNNN` y `%uNNNN`: `countMatches(payload, /(\\u[0-9a-fA-F]{4}\|\\U[0-9a-fA-F]{8}\|%u[0-9a-fA-F]{4})/gi)` | Evasión | O(n) | No |
| 24 | `html_entity_count` | E | Número de entidades HTML (named: `&amp;`, decimal: `&#60;`, hex: `&#x3C;`): `countMatches(payload, /(&[a-zA-Z]+;\|&#\d+;\|&#x[0-9a-fA-F]+;)/gi)` | XSS / Evasión | O(n) | No |
| 25 | `base64_like_count` | E | Número de subcadenas de ≥ 20 caracteres del alfabeto base64 (`[A-Za-z0-9+/]`) seguidas de 0–2 `=`: `countMatches(payload, /[A-Za-z0-9+\/]{20,}={0,2}/g)` | Evasión | O(n) amortizado; regex sin backtracking en V8 para este patrón | **Sí** — el modelo utilizó esta feature en 3 153 nodos de división (0.86 % del total de splits; rango #20/66 por conteo de splits en el modelo ONNX exportado, proxy de importancia Gini). Tráfico legítimo con JWTs o hashes en parámetros GET puede activarla, elevando el riesgo de falsos positivos. Ver limitación en Fase 8.3 de la tesis |
| 26 | `sqli_keyword_count` | A | Número de ocurrencias del patrón `SQL_KEYWORDS_COUNT`: alternación de ~40 palabras clave SQL (SELECT, UNION, INSERT, DROP, EXEC, SLEEP, INFORMATION_SCHEMA, etc.) con word boundary `\b` y flag `/gi` | SQLi | O(n) — alternación compilada por el motor V8 | No |
| 27 | `sqli_keyword_density` | A | Densidad de keywords SQL normalizada por tokens: `sqli_keyword_count / max(tokenCount(payload), 1)` | SQLi | O(n) (requiere tokenCount) | No |
| 28 | `sqli_comment_count` | A | Número de indicadores de comentario SQL: `countMatches(payload, /(--\|#(?!\d)\|\/\*\|\*\/)/g)`. El `#` usa lookahead negativo para no confundir con colores CSS (`#fff`) | SQLi | O(n) | No |
| 29 | `sqli_operator_count` | A | Número de operadores de comparación SQL: `countMatches(payload, /(<>\|!=\|>=\|<=\|(?<![<>!])=(?!=))/g)`. El operador `=` usa lookbehind/lookahead para excluir `!=`, `<=`, `>=` y `==` | SQLi | O(n) — lookbehind de longitud fija, lineal | No |
| 30 | `quote_count` | A | Número de comillas simples o dobles: `countMatches(payload, /['"]/g)` | SQLi | O(n) | No |
| 31 | `semicolon_count` | A | Número de punto y coma: `countMatches(payload, /;/g)` | SQLi / CMDi | O(n) | No |
| 32 | `parenthesis_count` | A | Número de paréntesis de apertura y cierre: `countMatches(payload, /[()]/g)` | SQLi / XSS | O(n) | No |
| 33 | `union_present` | A | Indicador binario: 1 si `/\bunion\b/i` coincide en el payload, 0 si no | SQLi | O(n) | No |
| 34 | `select_present` | A | Indicador binario: 1 si `/\bselect\b/i` coincide en el payload, 0 si no | SQLi | O(n) | No |
| 35 | `xss_marker_count` | A | Número de ocurrencias del patrón `XSS_MARKER_COUNT`: tags HTML peligrosos (`<script>`, `<img>`, `<svg>`, `<iframe>`, `<body>`, `<input>`), event handlers (`onerror=`, `onload=`, etc.), `javascript:`, funciones `alert/confirm/prompt`, `document.cookie`, `window.location`, `eval`, `innerHTML`, `src=javascript` — flag `/gi` | XSS | O(n) | No |
| 36 | `xss_marker_density` | A | Densidad porcentual de marcadores XSS: `(xss_marker_count / max(payload.length, 1)) × 100` | XSS | O(n) (requiere #35) | No |
| 37 | `html_tag_count` | A | Número de tags HTML (apertura o cierre): `countMatches(payload, /<[a-zA-Z\/]/g)` | XSS | O(n) | No |
| 38 | `script_tag_present` | A | Indicador binario: 1 si `/<\s*script/i` coincide (admite espacios entre `<` y `script`), 0 si no | XSS | O(n) | No |
| 39 | `js_event_handler_count` | A | Número de atributos de event handler inline (`onclick=`, `onmouseover=`, etc.): `countMatches(payload, /\bon[a-z]{2,20}\s*=/gi)` | XSS | O(n) | No |
| 40 | `javascript_url_count` | A | Número de ocurrencias del pseudo-protocolo `javascript:` (con posibles espacios): `countMatches(payload, /javascript\s*:/gi)` | XSS | O(n) | No |
| 41 | `html_entity_density` | A | Densidad porcentual de entidades HTML (mismo regex que #24): `(countMatches(payload, HTML_ENTITY_COUNT) / max(payload.length, 1)) × 100` | XSS / Evasión | O(n) | No |
| 42 | `alert_function_present` | A | Indicador binario: 1 si `/\b(?:alert\|confirm\|prompt)\s*\(/i` coincide, 0 si no | XSS | O(n) | No |
| 43 | `inline_style_present` | A | Indicador binario: 1 si `/\bstyle\s*=/i` coincide, 0 si no | XSS | O(n) | No |
| 44 | `traversal_sequence_count` | A | Número de secuencias de traversal de directorio en variantes literal y encoded: `countMatches(payload, /(\.\.[\\/]\|%2e%2e[%\\/]\|%252e%252e\|%c0%ae%c0%ae\|\.\.%2f\|\.\.%5c\|\.\.\/\|\.\.\\)/gi)` | Path Traversal | O(n) | No |
| 45 | `path_separator_count` | A | Número de separadores de path (Unix `/` y Windows `\`): `countMatches(payload, /[\/\\]/g)` | Path Traversal | O(n) | No |
| 46 | `absolute_path_indicator` | A | Indicador binario: 1 si el payload comienza con `/`, `\` o una unidad de disco Windows (`C:\`): `/^[\/\\]\|^[a-zA-Z]:[\/\\]/`.test(payload)` | Path Traversal | O(1) — regex anclada al inicio | No |
| 47 | `sensitive_file_target` | A | Indicador binario: 1 si el payload contiene rutas de archivos de sistema sensibles (`/etc/passwd`, `/etc/shadow`, `win.ini`, `boot.ini`, `.htaccess`, `.htpasswd`, `wp-config.php`, `.git/config`, `.env`, `.bash_history`, `/proc/self`, `web.config`, `php.ini`): `SENSITIVE_FILE_TEST.test(payload)` con flag `/i` | Path Traversal | O(n) | No |
| 48 | `sensitive_extension_count` | A | Número de extensiones de archivos de configuración/base de datos: `countMatches(payload, /\.(conf\|ini\|log\|bak\|env\|backup\|old\|sql\|db)\b/gi)` | Path Traversal | O(n) | No |
| 49 | `file_extension_suspicious` | A | Número de extensiones de archivos de script ejecutable del servidor: `countMatches(payload, /\.(php\d?\|aspx?\|jspx?)\b/gi)` | Path Traversal | O(n) | No |
| 50 | `dotdot_encoded_count` | A | Número de variantes encoded del patrón `..` (subconjunto de #44, solo la parte de doble punto): `countMatches(payload, /(%2e%2e\|%252e%252e\|%c0%ae)/gi)` | Path Traversal / Evasión | O(n) | No |
| 51 | `pipe_count` | A | Número de caracteres pipe `\|`: `countMatches(payload, /\|/g)` | CMDi | O(n) | No |
| 52 | `backtick_count` | A | Número de backticks `` ` ``: `countMatches(payload, /\`/g)` | CMDi | O(n) | No |
| 53 | `shell_command_count` | A | Número de ocurrencias de comandos shell Unix/Windows del patrón `SHELL_COMMAND_COUNT`: `cat`, `ls`, `dir`, `id`, `whoami`, `wget`, `curl`, `bash`, `sh`, `chmod`, `chown`, `rm`, `cp`, `mv`, `ping`, `nc`, `ncat`, `netcat`, `python`, `perl`, `ruby`, `php`, `powershell`, `cmd.exe`, `/bin/`, `/etc/passwd`, `/etc/shadow` — con word boundary y flag `/gi` | CMDi | O(n) | No |
| 54 | `command_separator_count` | A | Número de separadores de comandos shell: `countMatches(payload, /(&&\|\|\|\|[;\|;`])/g)` — cubre `&&`, `\|\|`, `\|`, `;` y backtick | CMDi | O(n) | No |
| 55 | `redirect_operator_count` | A | Número de operadores de redirección: `countMatches(payload, /(>>\|<<\|[><])/g)` — incluye `>>`, `<<`, `>`, `<`. Nota: `<` y `>` solapan con tags HTML (cf. #37) | CMDi | O(n) | No |
| 56 | `dollar_sign_count` | A | Número de signos `$`: `countMatches(payload, /\$/g)` | CMDi | O(n) | No |
| 57 | `subshell_count` | A | Número de construcciones de sustitución de comandos: `countMatches(payload, /(\$\(\|`[^`]+`)/g)` — cubre `$(...)` y `` `...` `` | CMDi | O(n) | No |
| 58 | `os_path_indicator` | A | Indicador binario: 1 si el payload contiene rutas de sistema Unix comunes (`/bin/`, `/etc/`, `/usr/`, `/var/`, `/proc/`, `/sys/`): `/(?:\/bin\/\|\/etc\/\|\/usr\/\|\/var\/\|\/proc\/\|\/sys\/)/.test(payload)` con flag `/i` | CMDi / Path Traversal | O(n) | No |
| 59 | `method_is_get` | B | Indicador binario: 1 si `method.toUpperCase() === "GET"`, 0 si no | General | O(1) | No |
| 60 | `method_is_post` | B | Indicador binario: 1 si `method.toUpperCase() === "POST"`, 0 si no | General | O(1) | No |
| 61 | `ua_present` | B | Indicador binario: 1 si `userAgent.length > 0`, 0 si no | General | O(1) | No |
| 62 | `ua_length` | B | Longitud del header User-Agent: `userAgent.length` | General | O(1) | No |
| 63 | `ua_suspicious` | B | Indicador binario: 1 si `SCANNER_UA_TEST` coincide con userAgent — patrón `/(?:sqlmap\|nikto\|dirb\|dirbuster\|nmap\|masscan\|nuclei\|burpsuite\|zaproxy\|w3af\|acunetix\|nessus\|openvas\|metasploit\|python-requests\|go-http\|curl\/\|wget\/\|libwww-perl\|httpclient)/i`. Fuente de verdad en `patterns.ts:SCANNER_UA_TEST` | General | O(n) — sobre cadena UA | No |
| 64 | `content_type_encoded` | B | Indicador binario: 1 si el Content-Type es `application/x-www-form-urlencoded`: `/application\/x-www-form-urlencoded/i.test(contentType)` | CMDi / General | O(n) — sobre cadena Content-Type | No |
| 65 | `authorization_length` | B | Longitud del header Authorization: `(extraHeaders["authorization"] ?? "").length` | General | O(1) | No |
| 66 | `unusual_headers_count` | B | Número de headers en `extraHeaders` que no pertenecen al conjunto estándar STANDARD_HEADERS = {host, user-agent, accept, content-type, content-length, authorization, cookie, referer, connection, accept-encoding, accept-language, cache-control}: itera sobre `Object.keys(extraHeaders)` y cuenta los no presentes en el Set | General | O(k) donde k = número de headers | No |
| 67 | `status_code` | B | Código de estado HTTP de la respuesta: `req.statusCode ?? 0`. **EXCLUIDA del modelo** — ver sección siguiente | — | O(1) | — |
| 68 | `req_count_1s` | — | Número de requests del mismo cliente en la última 1 segundo. **EXCLUIDA del modelo** — siempre 0 en runtime | — | — | — |
| 69 | `req_count_5s` | — | Número de requests del mismo cliente en los últimos 5 segundos. **EXCLUIDA del modelo** | — | — | — |
| 70 | `req_count_60s` | — | Número de requests del mismo cliente en los últimos 60 segundos. **EXCLUIDA del modelo** | — | — | — |
| 71 | `error_rate_4xx_60s` | — | Tasa de respuestas 4xx del cliente en los últimos 60 segundos. **EXCLUIDA del modelo** | — | — | — |
| 72 | `endpoint_diversity_60s` | — | Número de endpoints distintos visitados por el cliente en los últimos 60 segundos. **EXCLUIDA del modelo** | — | — | — |

---

## Features excluidas del modelo (66/72)

Las features #67–72 (índices 0-based: 66–71) se excluyen del vector de entrada al modelo ONNX:

```typescript
const EXCLUDED_FEATURE_INDICES = [66, 67, 68, 69, 70, 71];
// nombres: status_code, req_count_1s, req_count_5s, req_count_60s,
//          error_rate_4xx_60s, endpoint_diversity_60s
```

`status_code` (#67, índice 66) corresponde a un campo de respuesta HTTP que no existe en el momento en que el middleware intercepta la petición. Las cinco features temporales (#68–72, índices 67–71) requieren estado compartido entre requests (ventanas de tiempo de 1 s, 5 s y 60 s) que el extractor no mantiene por diseño (R1: la función `extractFeatureVector()` es pura y sin efectos secundarios). El extractor las incluye en las 72 features como indicadores de diagnóstico y para preservar compatibilidad con datasets de entrenamiento que sí disponen de esos valores (e.g., `owasp_logs`, `russellmitchell`), pero se eliminan antes de construir los splits de entrenamiento.

Para la justificación completa y el procedimiento de drop, ver [`training/FEATURE_NOTES.md`](../training/FEATURE_NOTES.md). La correcta exclusión está confirmada en [`training/models/parity_report.json`](../training/models/parity_report.json): `n_features=66`, `parity_passed=true`.

---

## Notas de implementación

### Precedencia de rawPayload

`deriveRawPayload()` en `index.ts` establece la prioridad body → query → path. Esto garantiza que requests POST (con body) no mezclen el análisis con el query string, y que requests GET que no tienen body analicen el query string como payload principal. Los grupos A–E (features 1–58) operan sobre este rawPayload unificado; las features de uri/path/query/body (features 3–7) sí distinguen los campos individuales.

### Riesgo de leakage

La feature #25 (`base64_like_count`) presenta riesgo de leakage confirmado por importancia: el modelo la usó en 3 153 nodos de división (rango #20/66 por conteo de splits en el modelo ONNX exportado — proxy de importancia Gini; rf_v1.pkl fue eliminado por `.gitignore` antes de poder extraer el valor sklearn exacto). Tráfico legítimo con JWTs, hashes de sesión o API keys en parámetros GET puede activar esta feature, ya que el umbral de ≥ 20 caracteres del alfabeto base64 no discrimina entre payload de ataque obfuscado y token legítimo largo. Este efecto se documenta como limitación de la tesis (Fase 8.3): en producción con tráfico autenticado vía Bearer tokens en URL, el clasificador puede exhibir una tasa de falsos positivos levemente elevada en esta dimensión específica.

### Solapamiento intencional entre grupos

- `redirect_operator_count` (#55) cuenta `<` y `>` además de `>>` y `<<`, lo que hace que payloads XSS (con tags HTML) activen levemente esta feature CMDi. Este solapamiento es intencional: contribuye como señal débil adicional en el clasificador multiclase.
- `sensitive_file_target` (#47) y `os_path_indicator` (#58) comparten rutas (`/etc/passwd`); ambas se mantienen porque ofrecen señales distintas (la primera detecta el archivo objetivo, la segunda el namespace de path del sistema operativo).
