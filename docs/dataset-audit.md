# Dataset Audit — logSguarDian

**Date:** 2026-06-20 (licenses verified and corpus counts re-checked against current `training/data_clean/` 2026-08-30)  
**Author:** Diego Valenzuela  
**Purpose:** Academic formalization of DATA_INVENTORY.md for PLAN.md task 2.1.  
Covers SPDX licenses, DOIs, APA 7 citations, and inclusion/exclusion decision per source.

> **Note:** Algorithm and methodology references (Breiman 2001, Liu et al. 2008, Chawla et al. 2002, etc.) are documented separately in PLAN.md §8.2. This document covers datasets only.

---

## Audit Table

| Source | License (SPDX) | DOI | Format | \# Records | Categories covered | Decision |
|--------|----------------|-----|--------|-----------|-------------------|----------|
| data_capec_multilabel.csv (SR-BH 2020) | **CC0-1.0** — confirmed via Harvard Dataverse API (`license.name: "CC0 1.0"`, `license.uri: creativecommons.org/publicdomain/zero/1.0`) | `10.7910/DVN/OGOIXX` | CSV | 289,287 in current `training/data_clean/capec.jsonl` (was 907,815 at audit time — see note below) | sqli, xss, path\_traversal, cmdi — **benign no longer present** (was listed at audit time; zero benign rows in the current corpus, see note below) | **Included** — largest multi-label coverage source; active parser bug in current parquet (see DATA\_INVENTORY §3) |
| modsec-learn | **MIT** — confirmed via LICENSE file at github.com/pralab/modsec-learn (GitHub's own license detection: `spdx_id: "MIT"`; repo name is `modsec-learn`, not `modsec-learn-dataset` as originally noted — corrected) | DOI not verified — associated paper: `10.1007/978-3-031-76459-2_3` | JSON (query string lists) | 539,074 (508,530 benign + 30,544 sqli) — matches current corpus exactly | sqli, benign | **Included** — largest source of real benign traffic; malicious assumed sqli (no explicit sub-type) |
| OWASP ModSec honeypot logs (Lucz & Forstner, 2025) | **CC BY 4.0** — confirmed via Zenodo API (`license.id: "cc-by-4.0"`) | `10.5281/zenodo.17178461` | ModSecurity audit log (sections A/B/F/H) | ~4,937,076 lines → 56,399 requests in current corpus (was reported as 56,504 at audit time — 105-row difference, likely a later dedup pass) | sqli, xss, path\_traversal, cmdi | **Included** — only dataset with full HTTP (URI, headers, body) and real CRS labels; zero benign samples (supplement required) |
| Payloads.csv | **CC BY 4.0** — confirmed via schema.org metadata embedded in the Kaggle page (`license.name: "Attribution 4.0 International (CC BY 4.0)"`) | DOI not verified — Kaggle does not assign DOIs; URL: kaggle.com/datasets/saurabhshahane/xss-attacks-dataset | CSV | 21,624 in current `training/data_clean/payloads_csv.jsonl` (was 43,217 at audit time — roughly halved, likely a dedup/filter pass since) | xss, benign | **Included** — good XSS coverage embedded in full URLs |
| payload\_full.csv | **MIT** — confirmed via schema.org metadata embedded in the Kaggle page (`license.name: "MIT"`) | DOI not verified — Kaggle does not assign DOIs; URL: kaggle.com/datasets/cyberprince/web-application-payloads-dataset | CSV | 31,067 — matches current corpus exactly | sqli, xss, path\_traversal, cmdi, benign | **Included** — only dataset with all 5 classes; cmdi extremely scarce (89 samples, unchanged) |
| XSS\_dataset.csv | **No license specified by the source** — Kaggle's own metadata explicitly reports `license.name: "Unknown"` for this dataset; confirmed honestly rather than assumed. No raw copy of this dataset is redistributed in this repository — only derived 73-feature vectors extracted from individual samples are retained in `training/data_clean/` | DOI not verified — Kaggle does not assign DOIs; URL: kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning | CSV | 13,570 in current `training/data_clean/xss_dataset.jsonl` (was 13,686 at audit time) | xss, benign | **Included** — additional XSS coverage; benign samples are Wikipedia fragments (domain mismatch, bias risk) |
| command injection.csv | **No license specified by the source** — Kaggle's own metadata explicitly reports `license.name: "Unknown"` for this dataset; confirmed honestly rather than assumed. No raw copy of this dataset is redistributed in this repository — only derived 73-feature vectors extracted from individual samples are retained in `training/data_clean/` | DOI not verified — Kaggle does not assign DOIs; URL: kaggle.com/datasets/sanketpawase/os-command-injection | CSV | 2,105 in current `training/data_clean/command_injection.jsonl` (514 cmdi + 1,591 benign — was reported as 478 attack samples at audit time) | cmdi, benign | **Included** — critical for underrepresented cmdi class despite small volume |
| omurugur Path Traversal Payload List | MIT (repo created 2019-05-29, confirmed via GitHub API) | DOI not assigned — GitHub does not assign DOIs; URL: github.com/omurugur/Path\_Travelsal\_Payload\_List | TXT (string lists) | 43,137 (all.txt) | path\_traversal | **Included** — MIT confirms free reuse; raw traversal strings without HTTP context |
| russellmitchell (AIT-LDSv2) | CC-BY-NC-SA-4.0 | `10.5281/zenodo.5789064` | Apache access logs + JSON labels | 3,435 | N/A — role labels (scan/dirb/foothold), not attack type | **Excluded** — labels describe attacker role, not payload type; no direct mapping to sqli/xss/path\_traversal/cmdi without manual re-labeling; mislabeling risk outweighs contribution (3,435 rows) |

> **Note on record-count drift (found while re-checking this table, 2026-08-30):** several sources' current row counts in `training/data_clean/` differ from what was recorded when this audit was first written (2026-06-20) — most notably SR-BH 2020/capec (907,815 → 289,287, and its `benign` rows are now entirely absent) and Payloads.csv (43,217 → 21,624, roughly halved). This reflects dedup/filter passes applied to the corpus across the v6–v10 retrain cycle, not a change in the source datasets themselves. Flagged here for transparency rather than silently updated without comment — the *sources* and their licenses are unaffected by this drift, only how much of each was ultimately retained in training.

---

## Items Requiring Manual Verification Before Defense — RESOLVED 2026-08-30

All 8 items below were pending as of the original 2026-06-20 audit. All are now resolved via authoritative sources (Harvard Dataverse API, Zenodo API, GitHub API, and Kaggle's own embedded schema.org metadata — see the Audit Table above for the confirmed value and citable source per entry). Kept here, marked resolved rather than deleted, as the verification paper trail:

| Dataset | Was pending | Resolution |
|---------|-------------|------------|
| SR-BH 2020 (capec) | Exact license on Harvard Dataverse (default CC0 but not confirmed) | **Resolved: CC0-1.0**, confirmed via Dataverse API |
| modsec-learn | License at github.com/pralab/modsec-learn-dataset/blob/main/LICENSE | **Resolved: MIT** — note the repo is actually `pralab/modsec-learn` (no separate `-dataset` repo exists; corrected in the Audit Table) |
| OWASP ModSec logs | License on Zenodo record 17178461 (likely CC-BY 4.0 per MDPI policy) | **Resolved: CC BY 4.0**, confirmed via Zenodo API — the original guess was correct |
| Payloads.csv | License on Kaggle page; publication year; formal DOI if available | **Resolved: CC BY 4.0**; author Saurabh Shahane; last modified 2021-11-20; Kaggle assigns no DOI (confirmed, not just assumed) |
| payload\_full.csv | License on Kaggle page; publication year; real author name | **Resolved: MIT**; real author name is Sunny Thakur (Kaggle handle "cyberprince"); last modified 2025-05-18 |
| XSS\_dataset.csv | License on Kaggle page; publication year | **Resolved: no license specified by the source** (Kaggle metadata literally reports "Unknown") — documented honestly rather than assumed; last modified 2020-03-17 |
| command injection.csv | License on Kaggle page; full author name (sanketpawase) | **Resolved: no license specified by the source** (Kaggle metadata literally reports "Unknown"); real full name is Sanket Pawase; last modified 2024-03-07 |
| omurugur wordlists | Repository creation year | **Resolved: 2019-05-29**, confirmed via GitHub API (license MIT reconfirmed the same way) |

> **Warning regarding russellmitchell (excluded):** The CC-BY-NC-SA-4.0 license prohibits commercial use. Exclusion is already decided on methodological grounds, but if inclusion were reconsidered for future work, verify compatibility with the final package license.

---

## APA 7 References — Included Datasets

The following references are ready for insertion into the thesis bibliography. All licenses and previously-pending fields were confirmed 2026-08-30 against authoritative sources (Harvard Dataverse API, Zenodo API, GitHub API, Kaggle's embedded schema.org metadata) — see the per-entry license notes below and the "RESOLVED" table above for citable sources.

---

**SR-BH 2020 / data_capec_multilabel.csv**

Sureda Riera, T., Bermejo Higuera, J.-R., Bermejo Higuera, J., Sicilia Montalvo, J.-A., & Martínez Herráiz, J.-J. (2020). *SR-BH 2020 multi-label dataset* [Data set]. Harvard Dataverse. https://doi.org/10.7910/DVN/OGOIXX

> License: CC0 1.0 (confirmed via the Harvard Dataverse API's `license` field — https://dataverse.harvard.edu/api/datasets/:persistentId/?persistentId=doi:10.7910/DVN/OGOIXX).

> Associated article: Sureda Riera, T., Bermejo Higuera, J.-R., Bermejo Higuera, J., Sicilia Montalvo, J.-A., & Martínez Herráiz, J.-J. (2022). A new multi-label dataset for Web attacks CAPEC classification using machine learning techniques. *Computers & Security*, *120*, 102788. https://doi.org/10.1016/j.cose.2022.102788

---

**modsec-learn**

Scano, C., Floris, G., Montaruli, B., Demetrio, L., Valenza, A., Compagna, L., Ariu, D., Piras, L., Balzarotti, D., & Biggio, B. (2024). *ModSec-Learn dataset* [Data set]. GitHub. https://github.com/pralab/modsec-learn

> License: MIT (confirmed via GitHub's license detection on the repository's LICENSE file). Corrected URL — `modsec-learn-dataset` is not a real repository; the dataset lives in a `data/` directory inside the main `modsec-learn` repo.

> Associated article: Scano, C., Floris, G., Montaruli, B., Demetrio, L., Valenza, A., Compagna, L., Ariu, D., Piras, L., Balzarotti, D., & Biggio, B. (2024). ModSec-Learn: Boosting ModSecurity with machine learning. In *Distributed Computing and Artificial Intelligence, 21st International Conference* (LNNS Vol. 1198, pp. 22–32). Springer. https://doi.org/10.1007/978-3-031-76459-2_3

---

**OWASP ModSec honeypot logs**

Lucz, G., & Forstner, B. (2025). *A thirty-day dataset of malicious HTTP requests blocked by OWASP ModSecurity on a production web server* [Data set]. Zenodo. https://doi.org/10.5281/zenodo.17178461

> License: CC BY 4.0 (confirmed via the Zenodo API's `metadata.license.id` field — https://zenodo.org/api/records/17178461). The original guess of "likely CC-BY 4.0 per MDPI policy" was correct.

> Associated article: Lucz, G., & Forstner, B. (2025). A thirty-day dataset of malicious HTTP requests blocked by OWASP ModSecurity on a production web server. *Data*, *10*(11), 186. https://doi.org/10.3390/data10110186

---

**Payloads.csv**

Shahane, S. (2021). *XSS attacks dataset* [Data set]. Kaggle. https://www.kaggle.com/datasets/saurabhshahane/xss-attacks-dataset

> License: CC BY 4.0 (confirmed via the page's embedded schema.org metadata). Year reflects Kaggle's recorded last-modified date (2021-11-20) — Kaggle's metadata does not separately expose an original publication date for this dataset.

---

**payload_full.csv**

Thakur, S. (2025). *Web application payloads dataset* [Data set]. Kaggle. https://www.kaggle.com/datasets/cyberprince/web-application-payloads-dataset

> License: MIT (confirmed via embedded metadata). Real author name is Sunny Thakur (Kaggle handle "cyberprince"). Year reflects last-modified date (2025-05-18).

---

**XSS_dataset.csv**

Shah, S. S. H. (2020). *Cross site scripting XSS dataset for deep learning* [Data set]. Kaggle. https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning

> License: not specified by the source — Kaggle's own metadata reports this field as "Unknown". Documented honestly rather than assumed; no raw copy of this dataset is redistributed in this repository, only derived feature vectors. Year reflects last-modified date (2020-03-17).

---

**command injection.csv**

Pawase, S. (2024). *OS command injection dataset* [Data set]. Kaggle. https://www.kaggle.com/datasets/sanketpawase/os-command-injection

> License: not specified by the source — Kaggle's own metadata reports this field as "Unknown". Documented honestly rather than assumed; no raw copy of this dataset is redistributed in this repository, only derived feature vectors. Real full name is Sanket Pawase. Year reflects last-modified date (2024-03-07).

---

**omurugur Path Traversal Payload List**

Uğur, Ö. (2019). *Path traversal vulnerability payload list* [Data set]. GitHub. https://github.com/omurugur/Path_Travelsal_Payload_List

> License: MIT (confirmed via GitHub API license detection). Repository created 2019-05-29.

---

## Excluded Dataset (reference for methodological transparency)

The following dataset was evaluated and excluded. The full reference is included to document the decision in the threats to validity section (PLAN.md §8.3).

Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M., & Rauber, A. (2022). *AIT log data set v2.0* [Data set]. Zenodo. https://doi.org/10.5281/zenodo.5789064

> Associated article: Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M., & Rauber, A. (2023). Maintainable log datasets for evaluation of intrusion detection systems. *IEEE Transactions on Dependable and Secure Computing*, *20*(4), 3466–3480. https://doi.org/10.1109/TDSC.2022.3201582

**Reason for exclusion:** The "russellmitchell" scenario labels describe attacker roles (`attacker_http`, `service_scan`, `foothold`, `dirb`) rather than payload types. There is no direct mapping to the target classes (sqli/xss/path_traversal/cmdi). Including attack traffic as benign would introduce mislabeling; including it as attack would require manually re-labeling each request. The methodological risk outweighs the contribution of 3,435 rows.
