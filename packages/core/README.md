# logsguardian

> Middleware RASP de deteccion de amenazas (SQLi, XSS, Path Traversal, Command Injection) para Node.js/Express.

**Estado: en desarrollo (skeleton).** Ver el [README raiz](../../README.md) para la descripcion general del proyecto.

## Estructura

- `src/index.ts` — punto de entrada publico
- `src/middleware.ts` — middleware Express (F5.3)
- `src/worker.ts` — worker_thread de inferencia ONNX (F5.2)
- `src/store.ts` — almacenamiento de eventos en SQLite (F5.5)
- `src/types.ts` — tipos publicos de la API (F5.1)
- `models/` — modelos ONNX (`rf.onnx`, `if.onnx`) y `model-metadata.json`, sincronizados desde `training/models/`

## Dependencias del workspace

Usa `@logsguardian/extractor` (paquete hermano en `packages/extractor`) para el vector canonico de 72 features.
