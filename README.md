# GTI_report_client

Application FastAPI + frontend statique pour explorer GTI et générer des rapports client.

## Reporting

- `Recent IoC Stream Sample Report` produit des synthèses agrégées: distribution par type d'indicateur, sévérité, sources, tendances temporelles, catégories de menace, industries ciblées disponibles et métriques de risque.
- Les rapports IoC Stream n'exposent pas les indicateurs individuels: IPs, domaines, URLs et hashes de fichiers sont exclus de la sortie client.
- `Top Targets Ranking` reste disponible pour les classements agrégés issus des collections GTI.

## Notes

L'ancien onglet de classements en direct et ses endpoints dédiés ont été retirés. Utiliser `Top Targets Ranking` pour générer des classements exploitables dans un rapport.
