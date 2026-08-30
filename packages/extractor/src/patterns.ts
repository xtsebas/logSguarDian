/**
 * Patrones regex portados desde data_manager/02_feature_engineering.ipynb
 * (celda cd_03). Deben mantenerse equivalentes byte a byte a los patrones
 * Python — cualquier divergencia rompe la paridad Python/TS exigida por el
 * gate 1.6 del plan de ejecucion.
 *
 * Convencion:
 *  - Sufijo COUNT  -> regex con flag global "g", usado con countMatches().
 *  - Sufijo TEST   -> regex sin flag "g", usado con .test() (sin estado).
 *  - Todos los patrones son case-insensitive salvo que el original no lo sea.
 */

// ---- Grupo 4: SQL Injection ----------------------------------------------
export const SQL_KEYWORDS_COUNT =
  /\b(select|union|insert|update|delete|drop|create|alter|exec(?:ute)?|where|from\b|into\b|null\b|like\b|between|exists|having|order\s+by|group\s+by|cast\b|convert\b|char\b|varchar|concat|count\b|sleep\b|benchmark|substr(?:ing)?|mid\b|ascii\b|hex\b|unhex|load_file|outfile|dumpfile|information_schema|schema\b|database\(|version\(|user\()/gi;

export const SQLI_COMMENT_COUNT = /(--|#(?!\d)|\/\*|\*\/)/g;
export const SQLI_OPERATOR_COUNT = /(<>|!=|>=|<=|(?<![<>!])=(?!=))/g;
export const UNION_PRESENT_TEST = /\bunion\b/i;
export const SELECT_PRESENT_TEST = /\bselect\b/i;
// Form-field separators (key= at the start of the payload or after &), used
// to subtract benign key=value structure out of sqli_operator_count.
export const FORM_FIELD_COUNT = /(^|&)[a-zA-Z_][a-zA-Z0-9_]*=/g;

// ---- Grupo 5: XSS ----------------------------------------------------------
export const XSS_MARKER_COUNT =
  /(<\s*script|<\s*\/\s*script|<\s*img|<\s*svg|<\s*iframe|<\s*body|<\s*input|on(?:error|load|click|mouseover|mouseout|focus|input|keyup|keydown)\s*=|javascript\s*:|alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie|window\.location|eval\s*\(|innerHTML|src\s*=\s*["']?\s*javascript)/gi;

export const HTML_TAG_COUNT = /<[a-zA-Z\/]/g;
export const SCRIPT_TAG_TEST = /<\s*script/i;
export const JS_EVENT_HANDLER_COUNT = /\bon[a-z]{2,20}\s*=/gi;
export const JAVASCRIPT_URL_COUNT = /javascript\s*:/gi;
export const ALERT_FUNCTION_TEST = /\b(?:alert|confirm|prompt)\s*\(/i;
export const INLINE_STYLE_TEST = /\bstyle\s*=/i;

// ---- Grupo 6: Path Traversal ----------------------------------------------
export const TRAVERSAL_SEQUENCE_COUNT =
  /(\.\.[\\/]|%2e%2e[%\\/]|%252e%252e|%c0%ae%c0%ae|\.\.%2f|\.\.%5c|\.\.\/|\.\.\\)/gi;

export const DOTDOT_ENCODED_COUNT = /(%2e%2e|%252e%252e|%c0%ae)/gi;
export const PATH_SEPARATOR_COUNT = /[\/\\]/g;
export const ABSOLUTE_PATH_TEST = /^[\/\\]|^[a-zA-Z]:[\/\\]/;

export const SENSITIVE_FILE_TEST =
  /(?:etc\/passwd|etc\/shadow|etc\/hosts|win\.ini|boot\.ini|\.htaccess|\.htpasswd|wp-config\.php|\.git\/config|\.env\b|\.bash_history|\/proc\/self|web\.config|php\.ini)/i;

export const SENSITIVE_EXTENSION_COUNT = /\.(conf|ini|log|bak|env|backup|old|sql|db)\b/gi;
export const SUSPICIOUS_EXTENSION_COUNT = /\.(php\d?|aspx?|jspx?)\b/gi;

// ---- Grupo 7: Command Injection -------------------------------------------
export const SHELL_COMMAND_COUNT =
  /\b(cat\b|ls\b|dir\b|id\b|whoami|wget\b|curl\b|bash\b|sh\b|chmod|chown|rm\b|cp\b|mv\b|ping\b|nc\b|ncat\b|netcat|python|perl|ruby|php\b|powershell|cmd\.exe|\/bin\/|\/etc\/passwd|\/etc\/shadow|certutil\b|wmic\b|reg\s+(add|query|delete)|net\s+(user|localgroup)|schtasks\b|rundll32\b|mshta\b|bitsadmin\b|Invoke-\w+|-enc\b|-EncodedCommand\b)/gi;

export const COMMAND_SEPARATOR_COUNT = /(&&|\|\||[|;`])/g;
export const REDIRECT_OPERATOR_COUNT = /(>>|<<|[><])/g;
export const SUBSHELL_COUNT = /(\$\(|`[^`]+`)/g;
export const OS_PATH_INDICATOR_TEST = /(?:\/bin\/|\/etc\/|\/usr\/|\/var\/|\/proc\/|\/sys\/)/i;

// ---- Grupo 3: Encoding ------------------------------------------------------
export const URL_ENCODED_COUNT = /%[0-9a-fA-F]{2}/g;
export const DOUBLE_ENCODED_COUNT = /%25[0-9a-fA-F]{2}/gi;
export const HEX_ESCAPE_COUNT = /(\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]+)/gi;
export const UNICODE_ESCAPE_COUNT = /(\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|%u[0-9a-fA-F]{4})/gi;
export const HTML_ENTITY_COUNT = /(&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;)/gi;
export const BASE64_LIKE_COUNT = /[A-Za-z0-9+\/]{20,}={0,2}/g;

// ---- Grupo 2: Composicion de caracteres ------------------------------------
export const SPECIAL_CHAR_COUNT = /[!@#$%^&*()\[\]{};:'",./<>?|\\=+_~`]/g;
export const NUMERIC_CHAR_COUNT = /\d/g;
export const UPPERCASE_CHAR_COUNT = /[A-Z]/g;
export const WHITESPACE_COUNT = /\s/g;
export const NEWLINE_CHAR_COUNT = /[\n\r]/g;
export const NEWLINE_ENCODED_COUNT = /%0[da]/gi;
export const NULL_BYTE_COUNT = /\x00/g;
export const NULL_BYTE_ENCODED_COUNT = /%00/gi;

// ---- Grupo 8: HTTP request ---------------------------------------------------
export const SCANNER_UA_TEST =
  /(?:sqlmap|nikto|dirb|dirbuster|nmap|masscan|nuclei|burpsuite|zaproxy|w3af|acunetix|nessus|openvas|metasploit|python-requests|go-http|curl\/|wget\/|libwww-perl|httpclient)/i;

export const CONTENT_TYPE_FORM_TEST = /application\/x-www-form-urlencoded/i;

/** Cuenta todas las coincidencias de un patron (debe tener flag "g"). */
export function countMatches(s: string, pattern: RegExp): number {
  if (!s) return 0;
  const matches = s.match(pattern);
  return matches ? matches.length : 0;
}
