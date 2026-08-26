# MLOps CT/CI/CD Pipeline — Fase 0: Decisión de alcance

**Fecha:** 2026-08-25
**Branch:** `feat/mlops-ctcicd-pipeline`

## Decisión

- **Tiempo disponible:** holgado (1+ mes antes de defensa). Se intentan las 8 fases completas.
- **Modo de despliegue del colector:** 100% local/simulado primero. Si sobra tiempo al final, se agrega despliegue real en un VPS barato como cereza del pastel (no bloqueante para el resto del plan).

## Alcance

Proof of concept end-to-end del ciclo completo: recolección → curación → reentrenamiento → gates → despliegue canario → rollback. Cada componente es real y ejecutable (no solo diagramado), corriendo sobre 3-5 "hosts" simulados localmente.

Todo el trabajo vive en `logSguarDian` (nuevo `packages/mlops/`), sin tocar `logSguarDian-vulnerable-project`.

## Secuencia de implementación

Fases 1→6 primero (recolección, simulación de flota, clustering IF, curación CLI, orquestación CT, gates automáticos) — son las que más fortalecen la tesis por menor esfuerzo relativo y reutilizan código existente casi al 100%. Fases 7-8 (canario en sombra, promoción/rollback) después, ya que tocan el worker pool y tienen mayor riesgo técnico.

Ver plan completo en el mensaje original de la tarea (no versionado aquí como archivo separado para evitar duplicación).
