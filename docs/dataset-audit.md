# Dataset Audit — logSguarDian

**Date:** 2026-06-20  
**Author:** Diego Valenzuela  
**Purpose:** Academic formalization of DATA_INVENTORY.md for PLAN.md task 2.1.  
Covers SPDX licenses, DOIs, APA 7 citations, and inclusion/exclusion decision per source.

> **Note:** Algorithm and methodology references (Breiman 2001, Liu et al. 2008, Chawla et al. 2002, etc.) are documented separately in PLAN.md §8.2. This document covers datasets only.

---

## Audit Table

| Source | License (SPDX) | DOI | Format | \# Records | Categories covered | Decision |
|--------|----------------|-----|--------|-----------|-------------------|----------|
| data_capec_multilabel.csv (SR-BH 2020) | Not specified — verify terms of use on Harvard Dataverse | `10.7910/DVN/OGOIXX` | CSV | 907,815 | sqli, xss, path\_traversal, cmdi, benign | **Included** — largest multi-label coverage source; active parser bug in current parquet (see DATA\_INVENTORY §3) |
| modsec-learn | Not specified — verify LICENSE at github.com/pralab/modsec-learn-dataset | DOI not verified — associated paper: `10.1007/978-3-031-76459-2_3` | JSON (query string lists) | 539,074 (508,530 benign + 30,544 sqli) | sqli, benign | **Included** — largest source of real benign traffic; malicious assumed sqli (no explicit sub-type) |
| OWASP ModSec honeypot logs (Lucz & Forstner, 2025) | Not specified — verify terms on Zenodo record 17178461 | `10.5281/zenodo.17178461` | ModSecurity audit log (sections A/B/F/H) | ~4,937,076 lines → 56,504 requests parsed | sqli, xss, path\_traversal, cmdi | **Included** — only dataset with full HTTP (URI, headers, body) and real CRS labels; zero benign samples (supplement required) |
| Payloads.csv | Not specified — verify terms of use on Kaggle (saurabhshahane) | DOI not verified — Kaggle does not assign DOIs; URL: kaggle.com/datasets/saurabhshahane/xss-attacks-dataset | CSV | 43,217 | xss, benign | **Included** — good XSS coverage embedded in full URLs |
| payload\_full.csv | Not specified — verify terms of use on Kaggle (cyberprince) | DOI not verified — Kaggle does not assign DOIs; URL: kaggle.com/datasets/cyberprince/web-application-payloads-dataset | CSV | 31,067 | sqli, xss, path\_traversal, cmdi, benign | **Included** — only dataset with all 5 classes; cmdi extremely scarce (89 samples) |
| XSS\_dataset.csv | Not specified — verify terms of use on Kaggle (syedsaqlainhussain) | DOI not verified — Kaggle does not assign DOIs; URL: kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning | CSV | 13,686 | xss, benign | **Included** — additional XSS coverage; benign samples are Wikipedia fragments (domain mismatch, bias risk) |
| command injection.csv | Not specified — verify terms of use on Kaggle (sanketpawase) | DOI not verified — Kaggle does not assign DOIs; URL: kaggle.com/datasets/sanketpawase/os-command-injection | CSV | 2,106 | cmdi, benign | **Included** — critical for underrepresented cmdi class (478 attack samples) despite small volume |
| omurugur Path Traversal Payload List | MIT | DOI not assigned — GitHub does not assign DOIs; URL: github.com/omurugur/Path\_Travelsal\_Payload\_List | TXT (string lists) | 43,137 (all.txt) | path\_traversal | **Included** — MIT confirms free reuse; raw traversal strings without HTTP context |
| russellmitchell (AIT-LDSv2) | CC-BY-NC-SA-4.0 | `10.5281/zenodo.5789064` | Apache access logs + JSON labels | 3,435 | N/A — role labels (scan/dirb/foothold), not attack type | **Excluded** — labels describe attacker role, not payload type; no direct mapping to sqli/xss/path\_traversal/cmdi without manual re-labeling; mislabeling risk outweighs contribution (3,435 rows) |

---

## Items Requiring Manual Verification Before Defense

The following fields could not be confirmed from accessible public sources and must be verified directly:

| Dataset | Pending |
|---------|---------|
| SR-BH 2020 (capec) | Exact license on Harvard Dataverse (default CC0 but not confirmed) |
| modsec-learn | License at github.com/pralab/modsec-learn-dataset/blob/main/LICENSE |
| OWASP ModSec logs | License on Zenodo record 17178461 (likely CC-BY 4.0 per MDPI policy) |
| Payloads.csv | License on Kaggle page; publication year; formal DOI if available |
| payload\_full.csv | License on Kaggle page; publication year; real author name |
| XSS\_dataset.csv | License on Kaggle page; publication year |
| command injection.csv | License on Kaggle page; full author name (sanketpawase) |
| omurugur wordlists | Repository creation year |

> **Warning regarding russellmitchell (excluded):** The CC-BY-NC-SA-4.0 license prohibits commercial use. Exclusion is already decided on methodological grounds, but if inclusion were reconsidered for future work, verify compatibility with the final package license.

---

## APA 7 References — Included Datasets

The following references are ready for insertion into the thesis bibliography. Fields marked *[verify]* require manual confirmation before submission.

---

**SR-BH 2020 / data_capec_multilabel.csv**

Sureda Riera, T., Bermejo Higuera, J.-R., Bermejo Higuera, J., Sicilia Montalvo, J.-A., & Martínez Herráiz, J.-J. (2020). *SR-BH 2020 multi-label dataset* [Data set]. Harvard Dataverse. https://doi.org/10.7910/DVN/OGOIXX

> Associated article: Sureda Riera, T., Bermejo Higuera, J.-R., Bermejo Higuera, J., Sicilia Montalvo, J.-A., & Martínez Herráiz, J.-J. (2022). A new multi-label dataset for Web attacks CAPEC classification using machine learning techniques. *Computers & Security*, *120*, 102788. https://doi.org/10.1016/j.cose.2022.102788

---

**modsec-learn**

Scano, C., Floris, G., Montaruli, B., Demetrio, L., Valenza, A., Compagna, L., Ariu, D., Piras, L., Balzarotti, D., & Biggio, B. (2024). *ModSec-Learn dataset* [Data set]. GitHub. https://github.com/pralab/modsec-learn-dataset

> Associated article: Scano, C., Floris, G., Montaruli, B., Demetrio, L., Valenza, A., Compagna, L., Ariu, D., Piras, L., Balzarotti, D., & Biggio, B. (2024). ModSec-Learn: Boosting ModSecurity with machine learning. In *Distributed Computing and Artificial Intelligence, 21st International Conference* (LNNS Vol. 1198, pp. 22–32). Springer. https://doi.org/10.1007/978-3-031-76459-2_3

---

**OWASP ModSec honeypot logs**

Lucz, G., & Forstner, B. (2025). *A thirty-day dataset of malicious HTTP requests blocked by OWASP ModSecurity on a production web server* [Data set]. Zenodo. https://doi.org/10.5281/zenodo.17178461

> Associated article: Lucz, G., & Forstner, B. (2025). A thirty-day dataset of malicious HTTP requests blocked by OWASP ModSecurity on a production web server. *Data*, *10*(11), 186. https://doi.org/10.3390/data10110186

---

**Payloads.csv**

saurabhshahane. (n.d.). *XSS attacks dataset* [Data set]. Kaggle. https://www.kaggle.com/datasets/saurabhshahane/xss-attacks-dataset [*Verify publication year and license on the Kaggle page*]

---

**payload_full.csv**

cyberprince. (n.d.). *Web application payloads dataset* [Data set]. Kaggle. https://www.kaggle.com/datasets/cyberprince/web-application-payloads-dataset [*Verify publication year, real author name, and license on the Kaggle page*]

---

**XSS_dataset.csv**

Shah, S. S. H. (n.d.). *Cross site scripting XSS dataset for deep learning* [Data set]. Kaggle. https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning [*Verify publication year and license on the Kaggle page*]

---

**command injection.csv**

sanketpawase. (2024). *OS command injection dataset* [Data set]. Kaggle. https://www.kaggle.com/datasets/sanketpawase/os-command-injection [*Verify full author name and license on the Kaggle page*]

---

**omurugur Path Traversal Payload List**

Uğur, Ö. (n.d.). *Path traversal vulnerability payload list* [Data set]. GitHub. https://github.com/omurugur/Path_Travelsal_Payload_List [*Verify repository creation year; MIT license confirmed*]

---

## Excluded Dataset (reference for methodological transparency)

The following dataset was evaluated and excluded. The full reference is included to document the decision in the threats to validity section (PLAN.md §8.3).

Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M., & Rauber, A. (2022). *AIT log data set v2.0* [Data set]. Zenodo. https://doi.org/10.5281/zenodo.5789064

> Associated article: Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M., & Rauber, A. (2023). Maintainable log datasets for evaluation of intrusion detection systems. *IEEE Transactions on Dependable and Secure Computing*, *20*(4), 3466–3480. https://doi.org/10.1109/TDSC.2022.3201582

**Reason for exclusion:** The "russellmitchell" scenario labels describe attacker roles (`attacker_http`, `service_scan`, `foothold`, `dirb`) rather than payload types. There is no direct mapping to the target classes (sqli/xss/path_traversal/cmdi). Including attack traffic as benign would introduce mislabeling; including it as attack would require manually re-labeling each request. The methodological risk outweighs the contribution of 3,435 rows.
