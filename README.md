# GTI_report_client
This is an application to get quick and fast data from GTI and generate reports from it.

## Sources de données entreprises

La route `GET /api/companies` utilise trois tentatives successives pour agréger les organisations les plus ciblées (réponse : `{"year", "source", "data": [{rank, name, collection_count}]}`).

1. **DTM (Digital Threat Monitoring)** — `GET /api/v3/dtm/events`, paramètre `limit=40` et `query=<target>` si un filtre est fourni. Extrait les champs `entity`, `organization`, `victim`, etc. depuis les attributs de chaque événement. Si le plan GTI ne couvre pas DTM (HTTP 403 ou 404), passe silencieusement à la tentative suivante. Source retournée : `"dtm"`.

2. **Intelligence Search** — `GET /api/v3/intelligence/search`, requête construite dynamiquement : `entity:collection <target> creation_date:<year>-01-01+..<year>-12-31+`. Parcourt jusqu'à 3 pages via le curseur GTI et extrait les organisations depuis les champs `targeted_organizations`, `victims` et `organizations` du preview. Retourne `None` si aucune organisation n'est trouvée (passe à la tentative 3). Source retournée : `"search"`.

3. **Actors fallback** — Réutilise `aggregate_top_targets()` (déjà implémenté pour le Top Targets Ranking) et extrait la liste `top_companies`. Toujours disponible quelle que soit la couverture GTI. Source retournée : `"actors"`.

La source active est affichée sous le graphique entreprises sous forme de badge (`via DTM`, `via Search`, `via Actors`).

Les deux routes `GET /api/industries` et `GET /api/companies` partagent les mêmes paramètres : `year` (défaut 2024), `top` (défaut 10), `target` (optionnel). L'en-tête `x-api-key` est obligatoire. Les résultats sont mis en cache 5 minutes côté serveur.
