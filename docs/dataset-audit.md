# Auditoría de Datasets — logSguarDian

**Fecha:** 2026-06-20  
**Autor:** Diego Valenzuela  
**Propósito:** Formalización académica de DATA_INVENTORY.md para PLAN.md tarea 2.1.  
Cubre licencias SPDX, DOIs, citaciones APA 7 y decisión de inclusión/descarte por fuente.

> **Nota:** Las referencias de algoritmos y metodología (Breiman 2001, Liu et al. 2008, Chawla et al. 2002, etc.) se documentan por separado en PLAN.md §8.2. Este documento cubre únicamente los datasets.

---

## Tabla de Auditoría

| Fuente | Licencia (SPDX) | DOI | Formato | \# Registros | Categorías cubiertas | Decisión |
|--------|-----------------|-----|---------|-------------|----------------------|----------|
| data_capec_multilabel.csv (SR-BH 2020) | No especificada — verificar términos de uso en Harvard Dataverse | `10.7910/DVN/OGOIXX` | CSV | 907,815 | sqli, xss, path\_traversal, cmdi, benign | **Incluido** — mayor fuente de cobertura multietiqueta; bug de parser activo en parquet actual (ver DATA\_INVENTORY §3) |
| modsec-learn | No especificada — verificar LICENSE en github.com/pralab/modsec-learn-dataset | DOI no verificado — paper asociado: `10.1007/978-3-031-76459-2_3` | JSON (listas de query strings) | 539,074 (508,530 benign + 30,544 sqli) | sqli, benign | **Incluido** — mayor fuente de tráfico benigno real; malicioso asumido sqli (sin sub-tipo explícito) |
| OWASP ModSec honeypot logs (Lucz & Forstner, 2025) | No especificada — verificar términos en Zenodo record 17178461 | `10.5281/zenodo.17178461` | ModSecurity audit log (secciones A/B/F/H) | ~4,937,076 líneas → 56,504 requests parseados | sqli, xss, path\_traversal, cmdi | **Incluido** — único dataset con HTTP completo (URI, headers, body) y etiquetas CRS reales; cero muestras benignas (complementar) |
| Payloads.csv | No especificada — verificar términos de uso en Kaggle (saurabhshahane) | DOI no verificado — Kaggle no asigna DOIs; URL: kaggle.com/datasets/saurabhshahane/xss-attacks-dataset | CSV | 43,217 | xss, benign | **Incluido** — buena cobertura de XSS embebido en URLs completas |
| payload\_full.csv | No especificada — verificar términos de uso en Kaggle (cyberprince) | DOI no verificado — Kaggle no asigna DOIs; URL: kaggle.com/datasets/cyberprince/web-application-payloads-dataset | CSV | 31,067 | sqli, xss, path\_traversal, cmdi, benign | **Incluido** — único dataset con las 5 clases; cmdi extremadamente escaso (89 muestras) |
| XSS\_dataset.csv | No especificada — verificar términos de uso en Kaggle (syedsaqlainhussain) | DOI no verificado — Kaggle no asigna DOIs; URL: kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning | CSV | 13,686 | xss, benign | **Incluido** — cobertura adicional XSS; benignas son fragmentos Wikipedia (domain mismatch, riesgo de sesgo) |
| command injection.csv | No especificada — verificar términos de uso en Kaggle (sanketpawase) | DOI no verificado — Kaggle no asigna DOIs; URL: kaggle.com/datasets/sanketpawase/os-command-injection | CSV | 2,106 | cmdi, benign | **Incluido** — crítico para clase subrepresentada cmdi (478 muestras ataque) a pesar del volumen pequeño |
| omurugur Path Traversal Payload List | MIT | DOI no asignado — GitHub no asigna DOIs; URL: github.com/omurugur/Path\_Travelsal\_Payload\_List | TXT (listas de strings) | 43,137 (all.txt) | path\_traversal | **Incluido** — MIT confirma reutilización libre; strings de traversal puras sin contexto HTTP |
| russellmitchell (AIT-LDSv2) | CC-BY-NC-SA-4.0 | `10.5281/zenodo.5789064` | Apache access logs + JSON labels | 3,435 | N/A — etiquetas de rol (scan/dirb/foothold), no de tipo de ataque | **Descartado** — etiquetas describen rol del atacante, no tipo de payload; imposible mapear a sqli/xss/path\_traversal/cmdi sin re-etiquetar manualmente; riesgo de mislabeling supera contribución (3,435 filas) |

---

## Items que requieren verificación manual antes de defensa

Los siguientes campos no pudieron confirmarse desde fuentes públicas accesibles y deben verificarse directamente:

| Dataset | Pendiente |
|---------|-----------|
| SR-BH 2020 (capec) | Licencia exacta en Harvard Dataverse (default CC0 pero no confirmado) |
| modsec-learn | Licencia en github.com/pralab/modsec-learn-dataset/blob/main/LICENSE |
| OWASP ModSec logs | Licencia en Zenodo record 17178461 (probable CC-BY 4.0 por política MDPI) |
| Payloads.csv | Licencia en página Kaggle; año de publicación; DOI formal si disponible |
| payload\_full.csv | Licencia en página Kaggle; año de publicación; nombre real del autor |
| XSS\_dataset.csv | Licencia en página Kaggle; año de publicación |
| command injection.csv | Licencia en página Kaggle; nombre completo del autor (sanketpawase) |
| omurugur wordlists | Año de creación del repositorio |

> **Advertencia sobre russellmitchell (descartado):** La licencia CC-BY-NC-SA-4.0 prohíbe uso comercial. El descarte ya está decidido por razones metodológicas, pero si se reconsiderara la inclusión para trabajos futuros, verificar compatibilidad con la licencia del paquete final.

---

## Referencias APA 7 — Datasets incluidos

Las siguientes referencias están listas para insertar en la bibliografía de la tesis. Los campos marcados *[verificar]* requieren confirmación manual antes de la entrega.

---

**SR-BH 2020 / data_capec_multilabel.csv**

Sureda Riera, T., Bermejo Higuera, J.-R., Bermejo Higuera, J., Sicilia Montalvo, J.-A., & Martínez Herráiz, J.-J. (2020). *SR-BH 2020 multi-label dataset* [Data set]. Harvard Dataverse. https://doi.org/10.7910/DVN/OGOIXX

> Artículo asociado: Sureda Riera, T., Bermejo Higuera, J.-R., Bermejo Higuera, J., Sicilia Montalvo, J.-A., & Martínez Herráiz, J.-J. (2022). A new multi-label dataset for Web attacks CAPEC classification using machine learning techniques. *Computers & Security*, *120*, 102788. https://doi.org/10.1016/j.cose.2022.102788

---

**modsec-learn**

Scano, C., Floris, G., Montaruli, B., Demetrio, L., Valenza, A., Compagna, L., Ariu, D., Piras, L., Balzarotti, D., & Biggio, B. (2024). *ModSec-Learn dataset* [Data set]. GitHub. https://github.com/pralab/modsec-learn-dataset

> Artículo asociado: Scano, C., Floris, G., Montaruli, B., Demetrio, L., Valenza, A., Compagna, L., Ariu, D., Piras, L., Balzarotti, D., & Biggio, B. (2024). ModSec-Learn: Boosting ModSecurity with machine learning. En *Distributed Computing and Artificial Intelligence, 21st International Conference* (LNNS Vol. 1198, pp. 22–32). Springer. https://doi.org/10.1007/978-3-031-76459-2_3

---

**OWASP ModSec honeypot logs**

Lucz, G., & Forstner, B. (2025). *A thirty-day dataset of malicious HTTP requests blocked by OWASP ModSecurity on a production web server* [Data set]. Zenodo. https://doi.org/10.5281/zenodo.17178461

> Artículo asociado: Lucz, G., & Forstner, B. (2025). A thirty-day dataset of malicious HTTP requests blocked by OWASP ModSecurity on a production web server. *Data*, *10*(11), 186. https://doi.org/10.3390/data10110186

---

**Payloads.csv**

saurabhshahane. (s.f.). *XSS attacks dataset* [Data set]. Kaggle. https://www.kaggle.com/datasets/saurabhshahane/xss-attacks-dataset [*Verificar año de publicación y licencia en la página Kaggle*]

---

**payload_full.csv**

cyberprince. (s.f.). *Web application payloads dataset* [Data set]. Kaggle. https://www.kaggle.com/datasets/cyberprince/web-application-payloads-dataset [*Verificar año de publicación, nombre real del autor y licencia en la página Kaggle*]

---

**XSS_dataset.csv**

Shah, S. S. H. (s.f.). *Cross site scripting XSS dataset for deep learning* [Data set]. Kaggle. https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning [*Verificar año de publicación y licencia en la página Kaggle*]

---

**command injection.csv**

sanketpawase. (2024). *OS command injection dataset* [Data set]. Kaggle. https://www.kaggle.com/datasets/sanketpawase/os-command-injection [*Verificar nombre completo del autor y licencia en la página Kaggle*]

---

**omurugur Path Traversal Payload List**

Uğur, Ö. (s.f.). *Path traversal vulnerability payload list* [Data set]. GitHub. https://github.com/omurugur/Path_Travelsal_Payload_List [*Verificar año de creación del repositorio; licencia MIT confirmada*]

---

## Dataset descartado (referencia para transparencia metodológica)

El siguiente dataset fue evaluado y descartado. Se incluye la referencia completa para documentar la decisión en la sección de amenazas a la validez (PLAN.md §8.3).

Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M., & Rauber, A. (2022). *AIT log data set v2.0* [Data set]. Zenodo. https://doi.org/10.5281/zenodo.5789064

> Artículo asociado: Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M., & Rauber, A. (2023). Maintainable log datasets for evaluation of intrusion detection systems. *IEEE Transactions on Dependable and Secure Computing*, *20*(4), 3466–3480. https://doi.org/10.1109/TDSC.2022.3201582

**Razón de descarte:** Las etiquetas del escenario "russellmitchell" describen roles del atacante (`attacker_http`, `service_scan`, `foothold`, `dirb`) en lugar de tipos de payload. No existe mapeo directo a las clases objetivo (sqli/xss/path_traversal/cmdi). Incluir el tráfico de ataque como benigno introduciría mislabeling; incluirlo como ataque requeriría re-etiquetar manualmente cada request. El riesgo metodológico supera la contribución de 3,435 filas.
