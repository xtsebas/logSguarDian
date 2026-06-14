# Limitaciones conocidas — logSguarDian

Este documento recoge las limitaciones técnicas identificadas durante el desarrollo
y validación del sistema. Corresponde al contenido de la Sección 8.3 de la tesis
(Amenazas a la validez).

---

## 1. Detección de inyección de comandos (cmdi)

### Problema de separabilidad en espacio de features

La clase cmdi presenta el desempeño más bajo del modelo (F1 = 0.902 con la
configuración final) y fue la única que impidió reducir el tamaño del modelo
sin perder calidad. La raíz del problema es estructural: los patrones de
inyección de comandos (separadores de shell como `|`, `;`, `` ` ``; nombres de
binarios como `/bin/sh`, `/etc/passwd`; operadores de redirección `>`, `>>`)
comparten features con tráfico benigno (rutas legítimas de sistemas de archivos)
y con ataques de path traversal. En el espacio de 66 dimensiones extraídas por
el extractor, cmdi no es linealmente separable de estas clases a profundidades
de árbol moderadas.

### Experimento SMOTE — resultado negativo

Se aplicó SMOTE al conjunto de entrenamiento para aumentar la clase cmdi de 3 881
muestras reales a 25 000 (3 881 reales + 21 119 sintéticas). La mejora obtenida
fue marginal: +0.015 en F1 a max_depth=15 (0.593 → 0.608) y sin mejora a
max_depth=20. SMOTE opera en espacio de features mediante interpolación lineal
entre vectores reales — no genera nuevas payloads textuales. Los vectores
sintéticos pueden producir combinaciones que no corresponden a ningún ataque
real (por ejemplo, `shell_command_count > 0` y `sqli_keyword_count > 0`
simultáneamente), pero no abren nuevas fronteras de decisión en zonas del espacio
que el árbol ya no puede resolver con profundidad insuficiente. El experimento
confirmó que el problema es de **separabilidad**, no de **cantidad de muestras**.

### Solución adoptada

El modelo final usa max_depth=25, que provee suficientes bifurcaciones para aislar
las combinaciones de features que distinguen cmdi del tráfico benigno y del
path traversal. Con esta profundidad, cmdi alcanza F1 = 0.902.

La implicación práctica es que el modelo no puede reducirse a profundidades menores
de 25 sin sacrificar la detección de cmdi. Si en el futuro se requiere un modelo
más ligero, las alternativas son: (a) arquitecturas con representación más compacta
(XGBoost, LightGBM); (b) features adicionales que mejoren la separabilidad de cmdi
(por ejemplo, análisis de secuencias de tokens de shell en el payload).

---

## 2. Factor de expansión de memoria en ONNX Runtime

El operador `TreeEnsembleClassifier` de ONNX Runtime materializa la estructura
completa de todos los árboles en memoria nativa C++ al crear la sesión. El factor
de expansión medido es ~1.264 KB por nodo: el modelo original (rf_v1, 367 655
nodos, 44 MB en disco) consumió 465 MB de RSS al cargarse. El modelo final
(rf_v2, 180 022 nodos, 10.8 MB en disco) consume 122 MB de RSS, lo que representa
una reducción del 74 % con pérdida de 0.005 en macro F1.

Este comportamiento es inherente a la implementación de ORT para Random Forests y
no puede mitigarse con configuración de sesión. Modelos futuros deben estimar el
footprint de memoria como `n_nodes × 1.264 KB` antes de fijar gates de memoria.

---

## 3. base64_like_count — riesgo de leakage

El feature `base64_like_count` (#25 en la especificación) cuenta secuencias de
caracteres que parecen base64 en el payload. En ataques reales, los atacantes pueden
codificar payloads en base64 para evadir detección — esto significa que el feature
puede correlacionar con la etiqueta de ataque no solo por el contenido semántico
del payload, sino por la presencia de ofuscación base64 en el dataset de entrenamiento.

Análisis de importancia (ONNX node splits): rank #20 de 66 con 0.86 % de los splits
totales. Importancia moderada — el modelo depende de este feature pero no de forma
dominante. Limitación documentada en la Sección de Amenazas a la Validez: si el
corpus de entrenamiento sobrerrepresenta ataques con base64 respecto al tráfico
real, el modelo puede aprender una heurística de codificación en lugar de patrones
semánticos de ataque.

---

## 4. Cobertura de fuentes de datos

El sistema fue entrenado sobre datasets públicos (CAPEC, ModSecurity, OWASP,
payload corpora). El tráfico real de producción puede diferir en distribución de
longitudes, encoding, User-Agent, y combinaciones de features. La validación
leave-one-source-out (Task 3.6 en PLAN.md) está pendiente y medirá la degradación
por fuente.
