# logSguarDian — Plan de Ejecución Atómico

**Proyecto:** Middleware RASP con modelo híbrido ML para APIs Node.js/Express
**Autor:** Diego Valenzuela — Trabajo de graduación, Ingeniería en Ciencias de la Computación, UVG
**Estado de partida:** Datasets identificados. Cero código escrito.

---

## 0. Principios rectores del plan

Antes de las tareas, tres reglas que gobiernan todo el plan. Si una tarea las viola, la tarea está mal diseñada.

**R1 — Una sola implementación del extractor de features.** El riesgo metodológico más grande del proyecto no es el modelo: es que el vector de 72 dimensiones se calcule de una forma en Python (entrenamiento) y de otra en Node.js (producción). Una diferencia de 0.001 en una entropía invalida toda métrica reportada. Por eso el extractor se implementa **una sola vez, en TypeScript**, y el pipeline de entrenamiento en Python consume matrices de features ya extraídas por ese mismo código. Python nunca recalcula features.

**R2 — El conjunto de prueba se bloquea en la Fase 2 y no se toca hasta la Fase 5.** Toda decisión de tuning (hiperparámetros, umbral del Isolation Forest, selección de features) se toma contra el conjunto de validación. El conjunto de prueba se usa exactamente una vez por modelo, para el reporte final. Reportar métricas de validación como finales es causal de rechazo metodológico.

**R3 — Cada tarea termina con un criterio de aceptación verificable.** No existe "tarea terminada" sin evidencia: un test que pasa, un número medido, un archivo generado. Las tareas marcadas `[GATE]` bloquean el inicio de la fase siguiente.

---

## Fase 0 — Infraestructura del proyecto (≈ 1 semana)

| ID | Tarea | Entregable | Criterio de aceptación |
|----|-------|-----------|------------------------|
| 0.1 | Crear monorepo con estructura `packages/core` (librería npm, TS), `packages/extractor` (feature engineering, TS), `training/` (Python + notebooks), `datasets/` (gitignored, con scripts de descarga), `benchmarks/` | Repositorio en GitHub con README inicial | `npm install && npm test` corre en limpio (suite vacía OK) |
| 0.2 | Configurar tooling Node: TypeScript estricto, Jest, ESLint, tsup para build dual CJS/ESM | `tsconfig.json`, `jest.config`, pipeline de build | `npm run build` genera dist CJS+ESM con tipos |
| 0.3 | Configurar entorno Python reproducible: `uv` o `conda` con `requirements.txt` pinneado (scikit-learn, skl2onnx, onnxruntime, pandas, jupyter) | `training/requirements.txt` con versiones exactas | `pip install -r requirements.txt` reproduce el entorno en limpio; versiones de sklearn y skl2onnx compatibles documentadas |
| 0.4 | CI mínimo (GitHub Actions): lint + test en push | `.github/workflows/ci.yml` | Badge verde en el repo |
| 0.5 | Definir el **esquema canónico de solicitud** (`CanonicalRequest`): method, path, query, headers, body, content-type — el formato único al que se normalizan tanto los datasets como el `req` de Express | `packages/extractor/src/types.ts` + documento de diseño de 1 página | Tipo compila; todo dataset de la Fase 2 debe poder mapearse a él |

La tarea 0.5 es la bisagra del proyecto: si los 8 datasets y el objeto `req` de Express convergen al mismo esquema, R1 se vuelve trivial de cumplir.

---

## Fase 1 — Extractor de features (≈ 2-3 semanas)

Esta fase es la contribución diferenciadora de la tesis. Cada feature necesita justificación técnica vinculada a una categoría de ataque — eso se documenta aquí, no después.

| ID | Tarea | Entregable | Criterio de aceptación |
|----|-------|-----------|------------------------|
| 1.1 | Especificar el vector de ~72 dimensiones en una **tabla de justificación**: nombre, fórmula, categoría de ataque que discrimina (SQLi/XSS/PT/CMDi/general), costo de cómputo estimado, riesgo de leakage | `docs/feature-spec.md` | Cada feature tiene las 5 columnas llenas; ninguna feature requiere estado entre requests; ninguna depende de timestamps |
| 1.2 | Implementar features estructurales: longitudes (path, query, body, headers), conteo de parámetros, profundidad de path, conteo de segmentos `..`, ratio de caracteres especiales | `extractor/src/structural.ts` + tests unitarios | 100% cobertura de ramas en estas funciones |
| 1.3 | Implementar features semánticas: entropía de Shannon por campo, densidad de marcadores SQLi (comillas, `UNION`, `--`, `;`), densidad de marcadores XSS (`<`, `script`, `on*=`, `javascript:`), marcadores de path traversal (`../`, `%2e`, rutas absolutas a `/etc`, `C:\`), marcadores de command injection (`;`, `|`, `` ` ``, `$(`, nombres de binarios comunes) | `extractor/src/semantic.ts` + tests | Tests con payloads de ejemplo por categoría: el payload activa la feature esperada |
| 1.4 | Implementar features de encoding: frecuencia de percent-encoding, doble encoding, ratio ASCII extendido, presencia de null bytes, mixed-case sospechoso en keywords | `extractor/src/encoding.ts` + tests | Idem 1.3 |
| 1.5 | Ensamblar `extractFeatures(req: CanonicalRequest): Float32Array` — dimensión fija, determinista, sin I/O | `extractor/src/index.ts` | Test de propiedad: para cualquier input, el vector tiene exactamente N dimensiones y valores finitos; mismo input → mismo output (determinismo) |
| 1.6 | **[GATE]** Test de determinismo cross-platform: ejecutar el extractor sobre 1,000 requests de muestra en macOS (ARM) y en CI (Linux x64), comparar vectores byte a byte | Reporte en CI | Diferencia = 0 en las 1,000 muestras |
| 1.7 | CLI de extracción batch: `extract --in dataset.jsonl --out features.csv` para alimentar a Python | `extractor/src/cli.ts` | Procesa 100k requests sin errores; throughput documentado |
| 1.8 | Benchmark del extractor aislado (sin modelo): p50/p95/p99 por request en el hilo principal | `benchmarks/extractor.bench.ts` | p95 documentado; si p95 > 1 ms, identificar las 3 features más costosas y optimizar o justificar |

**Señal de alerta a vigilar:** features que discriminan perfecto en un dataset pero son artefactos de ese dataset (ej. un header fijo que solo aparece en el tráfico malicioso de SR-BH). La tabla 1.1 debe marcar este riesgo por feature; la validación cruzada entre datasets en Fase 3 lo confirmará o descartará.

---

## Fase 2 — Construcción del dataset unificado (≈ 2-3 semanas)

| ID | Tarea | Entregable | Criterio de aceptación |
|----|-------|-----------|------------------------|
| 2.1 | Auditar licencia, formato y cobertura de cada uno de los 8 datasets; descartar los que no sean de capa de aplicación o no aporten al scope | `docs/dataset-audit.md` con tabla: fuente, DOI, licencia, formato, categorías cubiertas, # requests, decisión incluir/descartar | Cada dataset incluido tiene licencia abierta verificable y citación APA 7 lista |
| 2.2 | Escribir un parser por dataset → `CanonicalRequest` + etiqueta `{legit, sqli, xss, path_traversal, cmdi}` | `training/parsers/*.py` (o TS) con tests por parser | Cada parser procesa el 100% de su fuente o documenta explícitamente los registros descartados y por qué |
| 2.3 | Unificar etiquetas a taxonomía única (los datasets usan nombres distintos para las mismas clases) | `training/label_map.yaml` | Mapeo revisable; cero etiquetas "other" sin justificar |
| 2.4 | Deduplicación: exactos (hash del request canónico) y near-duplicates (similitud sobre el vector de features, ej. distancia < ε) | Script + reporte de duplicados removidos por fuente | % de duplicados por dataset documentado |
| 2.5 | Análisis exploratorio: distribución por clase, por fuente, longitudes, solapamiento entre fuentes | Notebook `01_eda.ipynb` | Tabla de desbalance por clase; decisión de mitigación (class weights vs SMOTE vs undersampling) tomada y justificada con cita (Chawla et al., 2002 si aplica SMOTE) |
| 2.6 | Partición estratificada train/val/test (ej. 70/15/15), estratificando por clase **y por fuente** para que ninguna fuente exista solo en una partición | `datasets/splits/` con manifiestos de hashes | Verificación automática: cero hashes compartidos entre particiones; distribución de clases por partición dentro de ±2% del global |
| 2.7 | **[GATE]** Bloquear el test set: archivo de hashes firmado, comprometido en git, con regla explícita de "no se lee hasta Fase 5" | `datasets/splits/test.lock.sha256` | Existe y está en el historial de git antes de cualquier entrenamiento |
| 2.8 | Extraer features de las 3 particiones con el CLI de 1.7 | `features_{train,val,test}.parquet` | Dimensión y conteo de filas coinciden con los manifiestos |

**Nota crítica sobre 2.4 + 2.6:** los near-duplicates entre particiones son la forma más común de leakage en este tipo de tesis (payloads de SQLi casi idénticos en train y test inflan el F1 artificialmente). La verificación de 2.6 debe correr también sobre near-duplicates, no solo hashes exactos.

---

## Fase 3 — Entrenamiento y evaluación (≈ 3 semanas)

| ID | Tarea | Entregable | Criterio de aceptación |
|----|-------|-----------|------------------------|
| 3.1 | Baseline trivial: regresión logística y árbol de decisión simple sobre las features, para tener punto de comparación honesto | Notebook `02_baseline.ipynb` | F1 macro del baseline documentado — el RF debe superarlo o la tesis tiene un problema |
| 3.2 | Entrenar Random Forest multiclase (5 clases: legit + 4 ataques); búsqueda de hiperparámetros (n_estimators, max_depth, class_weight) con CV estratificada de 5 folds **solo sobre train**, evaluando en val | `03_random_forest.ipynb` + `models/rf_vN.pkl` | Grid documentado; mejor configuración elegida por F1 macro en val |
| 3.3 | Evaluación del RF en val: classification_report por clase, matriz de confusión, curvas precision-recall | Sección del notebook + figuras exportadas | F1 ≥ 0.80 en ≥ 3 de 4 categorías de ataque **en val**; si no se alcanza, iterar features (volver a 1.x) antes de tocar el modelo |
| 3.4 | Análisis de importancia de features (impureza + permutation importance) y poda: eliminar features con contribución ~0 | Tabla de importancias; vector final de dimensión definitiva | La poda no degrada F1 en val más de 0.01; dimensión final documentada |
| 3.5 | Entrenar Isolation Forest **solo con tráfico legítimo de train**; calibrar contamination/umbral sobre val | `04_isolation_forest.ipynb` + `models/if_vN.pkl` | Curva recall-vs-FP sobre val; umbral elegido en la región recall ≥ 50% ∧ FP ≤ 10% |
| 3.6 | Validación cruzada entre fuentes (leave-one-source-out): entrenar sin una fuente, evaluar sobre ella | Tabla de degradación por fuente | Degradación documentada y discutida — esto es la evidencia de generalización para la tesis |
| 3.7 | Definir la **política de decisión híbrida**: cómo se combinan RF e IF en un veredicto único (ej. bloquear si RF ≥ umbral_clase O IF marca anomalía; o IF solo en modo alerta) | `docs/decision-policy.md` | Política expresada como pseudocódigo determinista con umbrales numéricos; justificación del tradeoff FP operacional |
| 3.8 | **[GATE]** Congelar modelos candidatos: `rf_final`, `if_final`, umbrales | Artefactos versionados con hash | Nada de esta fase se reentrena después del gate sin reabrir formalmente la fase |

**Regla del IF que no se negocia:** un Isolation Forest con FP = 0% y recall = 10% cumple "FP ≤ 10%" y es operacionalmente inútil. Ambas métricas se reportan siempre juntas, sobre la misma partición.

---

## Fase 4 — Serialización ONNX y paridad (≈ 1 semana)

| ID | Tarea | Entregable | Criterio de aceptación |
|----|-------|-----------|------------------------|
| 4.1 | Exportar RF e IF a ONNX con skl2onnx; desactivar `zipmap` para obtener tensores de probabilidad planos; fijar `target_opset` compatible con onnxruntime-node | `models/rf.onnx`, `models/if.onnx` + script de exportación | Exportación reproducible desde los .pkl congelados |
| 4.2 | Paridad Python: comparar predicciones sklearn vs onnxruntime (Python) sobre las features de **val** completa | Script `parity_py.py` | Diferencia de probabilidad máxima < 0.1%; clase predicha idéntica en 100% de casos |
| 4.3 | Paridad Node: cargar los .onnx en onnxruntime-node y comparar contra las salidas de 4.2 sobre el mismo set | Test Jest `parity.node.test.ts` | Mismo criterio que 4.2 |
| 4.4 | **[GATE]** Medir tamaño en disco y memoria de las sesiones ONNX cargadas en Node | Reporte | Memoria de ambas sesiones + runtime ≤ 150 MB; si excede, reducir n_estimators/max_depth y volver a 3.2 con presupuesto explícito |

La paridad se verifica **antes** de integrar al middleware. Cualquier métrica reportada desde Node sin 4.3 en verde es inválida.

---

## Fase 5 — Middleware Express (≈ 3 semanas)

| ID | Tarea | Entregable | Criterio de aceptación |
|----|-------|-----------|------------------------|
| 5.1 | Diseñar la API pública: `app.use(logsguardian({ mode: 'block' \| 'monitor', failOpen: true, timeoutMs: 5, ... }))` | `docs/api.md` | API revisada contra casos de uso: bloquear, solo alertar, excluir rutas (healthchecks, webhooks) |
| 5.2 | Implementar el worker_thread de inferencia: carga las sesiones ONNX **una vez** al arrancar, hace warmup (N inferencias dummy para JIT de V8 y caches de ORT), expone cola de mensajes | `core/src/worker.ts` + tests | Sesión persiste entre peticiones (verificado por test); warmup medible en logs |
| 5.3 | Implementar el middleware: normaliza `req` → `CanonicalRequest`, extrae features (decidir y documentar: ¿en hilo principal o en el worker? — medir ambas), envía al worker, aplica la política de decisión de 3.7 | `core/src/middleware.ts` | Tests Supertest: payload SQLi conocido → 403; request legítimo → pasa |
| 5.4 | Implementar política de timeout y fallo: si el worker no responde en `timeoutMs`, comportamiento según `failOpen` (default: la petición pasa y se registra el evento). Documentar el razonamiento de seguridad de fail-open como default | Tests de timeout con worker artificialmente lento | El proceso nunca queda colgado; el Event Loop nunca se bloquea esperando inferencia |
| 5.5 | Almacenamiento de eventos en SQLite (better-sqlite3): tabla de detecciones con timestamp, ruta, scores, veredicto, vector opcional; escritura fuera del camino crítico de la petición | `core/src/store.ts` + tests | Escritura asíncrona/batched; corrupción ante kill -9 no rompe el arranque siguiente |
| 5.6 | Manejo de cuerpos problemáticos: body no-JSON, multipart, body gigante (límite de bytes analizados), encoding raro | Tests de borde | Ningún input mata el proceso; límites configurables documentados |
| 5.7 | **[GATE]** Suite de detección end-to-end: app Express de prueba + corpus de payloads por categoría (subconjunto del test set bloqueado, ahora sí liberado) | `e2e/detection.test.ts` + reporte de métricas finales | Métricas finales sobre test set reportadas: F1 por clase del RF, recall/FP del IF — estas son las cifras de la tesis |

### CLI Commands — F5 scope

Four command groups implemented as `lg <group> <command>`:

#### lg endpoints
- `endpoints top` — ranked table of routes by attack frequency (route, method, incident count, risk score). Reads SQLite store.
- `endpoints profile <route>` — detail for a specific route: attack types, hourly distribution, source IPs. Reads SQLite store filtered by route.
- `endpoints report` — exports full endpoint analysis as JSON or CSV (`--format json|csv`, `--output <path>`).

#### lg attacks
- `attacks list` — catalog of all attack types classified in the current store. Includes type, count, last detected.
- `attacks inspect <type>` — technical detail for an attack type: highest-weight features, example payloads from training data, model detection rate for that class. Requires `docs/feature-spec.md` to be complete before implementation.
- `attacks summary` — distribution by endpoint, time period, severity. Flags: `--from <date>`, `--to <date>`, `--endpoint <route>`.

#### lg webhooks
- `webhooks add <url>` — registers a webhook (Slack, Discord, custom). Validates HTTPS. Returns generated ID.
- `webhooks list` — all registered webhooks: ID, URL, created, status.
- `webhooks test <id>` — sends a test payload identical to a real detection event. Returns destination HTTP status code.
- `webhooks remove <id>` — removes webhook by ID. Returns error if ID does not exist.

#### lg config
- `config init` — generates `logsguardian.config.js` with defaults in the current directory. Middleware must start without perceptible latency using this file unmodified.
- `config set <key> <value>` — modifies active config. Keys: `threshold` (float 0-1), `mode` (block|log), `model` (rf|if|hybrid). Validates types before writing.
- `config validate` — checks config coherence: threshold range, mode values, referenced model exists in `models/`. Returns errors or confirmation.
- `config show` — prints active config. Flags: `--format json|table`.

**Out of scope:** `attacks simulate` and all variants. Excluded due to offensive security implications outside current protocol scope. Documented as future work.

---

## Fase 6 — Benchmarks de rendimiento (≈ 1-2 semanas)

| ID | Tarea | Entregable | Criterio de aceptación |
|----|-------|-----------|------------------------|
| 6.1 | Línea base: app Express de referencia **sin** middleware, perfil de carga con Artillery (definir RPS y duración representativos), medir p50/p95/p99 | `benchmarks/baseline.yml` + resultados | Línea base estable (variación entre corridas < 5%) |
| 6.2 | Misma app **con** middleware en modo block, mismo perfil, con warmup previo | Resultados comparables | Δp95 ≤ 5 ms por solicitud; p95 end-to-end dentro de 5-10% de la línea base |
| 6.3 | Perfil de memoria bajo carga sostenida (≥ 30 min): RSS del proceso + worker | Gráfica de memoria en el tiempo | Δ memoria ≤ 150 MB; sin crecimiento monótono (leak) |
| 6.4 | Benchmark de degradación: ¿qué pasa a 2x y 5x la carga esperada? ¿La cola del worker crece sin límite? | Reporte | Comportamiento bajo saturación documentado; backpressure o descarte definido |
| 6.5 | **[GATE]** Tabla consolidada de métricas vs criterios de éxito del proyecto | `docs/results.md` | Cada criterio de la tesis con su valor medido, condición de medición y veredicto cumple/no cumple |

Las mediciones se hacen en hardware documentado (modelo, RAM, OS, versión de Node) y con el modelo caliente. Mediciones en frío se reportan aparte como "costo de arranque".

---

## Fase 7 — Empaquetado y publicación (≈ 1-2 semanas)

| ID | Tarea | Entregable | Criterio de aceptación |
|----|-------|-----------|------------------------|
| 7.1 | Decidir distribución de los .onnx: ¿dentro del paquete npm o descarga postinstall? Medir tamaño del tarball | Decisión documentada | `npm pack` < 50 MB o estrategia de descarga con verificación de hash |
| 7.2 | README de usuario: instalación, quickstart de 5 líneas, configuración, qué detecta y qué NO detecta (DDoS y brute force fuera de scope, explícito), limitaciones, política de fail-open | `README.md` | Un desarrollador externo integra la librería siguiendo solo el README |
| 7.3 | Licencia open source (MIT o Apache-2.0), SECURITY.md, CONTRIBUTING.md, aviso de propósito académico | Archivos en raíz | Compatible con las licencias de los datasets usados |
| 7.4 | CI de release: build, tests, paridad ONNX, publicación a npm con provenance | Workflow de release | `npm install logsguardian` funciona en un proyecto limpio Express |
| 7.5 | Versionado del modelo dentro del paquete: el paquete reporta versión de librería + versión de modelo en logs | Campo en metadata | Trazabilidad modelo↔código verificable |

---

## Fase 8 — Cierre académico (en paralelo desde Fase 3)

| ID | Tarea | Entregable | Criterio de aceptación |
|----|-------|-----------|------------------------|
| 8.1 | Mapear cada capítulo de la tesis a los artefactos del repo (la tabla 1.1, el audit 2.1, los notebooks, results.md) | Esqueleto del documento, APA 7 | Cada afirmación cuantitativa del documento tiene su fuente en un artefacto versionado |
| 8.2 | Referencias bibliográficas: Breiman 2001 (RF), Liu et al. 2008 (IF), Chawla et al. 2002 (SMOTE si aplica), Chandola et al. 2009 (anomalías), Fawcett 2006 (ROC), Pedregosa et al. 2011 (sklearn), Shiravi et al. 2012 (ground truth), + DOIs de los datasets | Bibliografía APA 7 | Cero referencias sin DOI/URL verificable |
| 8.3 | Sección de amenazas a la validez: leakage residual, representatividad de datasets vs tráfico real centroamericano, ataques evasivos no cubiertos | Sección redactada | Limitaciones reconocidas antes de que el tribunal las señale |

---

## Dependencias entre fases

```
F0 → F1 → F2 → F3 → F4 → F5 → F6 → F7
            ↑________|            
     (si F1 cambia features,      F8 corre en paralelo desde F3
      F2.8 y F3 se re-ejecutan)
```

Los GATEs (1.6, 2.7, 3.8, 4.4, 5.7, 6.5) son puntos de no retorno: cruzarlos sin cumplir el criterio acumula deuda que explota en la defensa de tesis.

## Registro de riesgos principales

| Riesgo | Impacto | Mitigación en el plan |
|---|---|---|
| Drift entre extractor de entrenamiento y producción | Invalida todas las métricas | R1: extractor único en TS (1.7, 2.8) |
| Leakage por near-duplicates | F1 inflado, indefendible | 2.4 + verificación 2.6 |
| Features que son artefactos de un dataset | Modelo que no generaliza | 3.6 leave-one-source-out |
| IF "cumple" con recall inútil | Componente no supervisado decorativo | 3.5 exige ambas métricas juntas |
| ONNX no reproduce a sklearn | Métricas en Node inválidas | F4 completa antes de integrar |
| Latencia p95 > 5 ms | Criterio de éxito fallido | 1.8 detecta temprano; presupuesto de cómputo por feature |
| Tamaño del modelo > 150 MB | Criterio fallido | 4.4 con loop de retorno a 3.2 |
