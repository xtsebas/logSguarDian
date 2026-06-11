/**
 * Portado desde _entropy_series() y _ext_ascii_ratio() en
 * data_manager/02_feature_engineering.ipynb (celda cd_04).
 */

/**
 * Entropia de Shannon sobre los bytes UTF-8 del string (no sobre
 * code points). Equivalente a:
 *   _, c = np.unique(np.frombuffer(x.encode("utf-8"), dtype=np.uint8), return_counts=True)
 *   p = c / c.sum()
 *   -np.sum(p * np.log2(p + 1e-12))
 */
export function shannonEntropy(s: string): number {
  if (!s) return 0;

  const bytes = Buffer.from(s, "utf-8");
  const counts = new Map<number, number>();
  for (const byte of bytes) {
    counts.set(byte, (counts.get(byte) ?? 0) + 1);
  }

  const total = bytes.length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / total;
    entropy += -(p * Math.log2(p + 1e-12));
  }
  return entropy;
}

/**
 * Proporcion de caracteres con code point > 127 (fuera de ASCII).
 *
 * NOTA: itera por code points (como Python `for c in x: ord(c)`), pero el
 * denominador usa `s.length` (unidades UTF-16), igual que Python usa
 * `len(x)` (code points). Para el alfabeto de ataques HTTP (ASCII/Latin-1)
 * ambos coinciden; difieren solo con caracteres fuera del BMP, que no
 * aparecen en los datasets de entrenamiento.
 */
export function extendedAsciiRatio(s: string): number {
  if (s.length === 0) return 0;

  let count = 0;
  for (const ch of s) {
    if (ch.codePointAt(0)! > 127) count++;
  }
  return count / Math.max(s.length, 1);
}
