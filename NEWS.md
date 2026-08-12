*Dernier commit pris en compte : 60f4c8678*

# Semaine du 13/04/2026 au 19/04/2026
## Amélioration de la traçabilité
Il est dorénavant possible de tracer beaucoup plus facilement les connexions IKE grâce à l'ajout d'identifiants uniques dans les journaux système lors de l'ouverture et la fermeture des sessions.

# Semaine du 06/04/2026 au 12/04/2026
## Générateur de nombres aléatoires
Le plugin Botan offre maintenant une plus grande flexibilité en permettant de configurer finement le type de générateur de nombres aléatoires (RNG) à utiliser pour les opérations cryptographiques.

# Semaine du 23/03/2026 au 29/03/2026
## Sécurité renforcée sur IPsec
Afin d'améliorer la conformité et la sécurité, les politiques IPsec sont désormais strictement rejetées si elles ne concernent pas le mode tunnel ESP.

# Semaine du 09/03/2026 au 15/03/2026
## Automatisation des configurations
L'installation et la gestion de Charon ont été simplifiées : des fragments de configuration de base sont désormais générés et installés automatiquement pour les utilitaires `charon-cmd` et `charon-nm`.

# Semaine du 23/02/2026 au 01/03/2026
## Validation des commandes swanctl
L'outil en ligne de commande `swanctl` effectue de nouvelles vérifications lors de l'enregistrement de ses commandes pour éviter les conflits avec des options déjà existantes ou partagées.

# Semaine du 27/10/2025 au 02/11/2025
## Mises à jour de l'application Android
L'application Android a reçu une importante mise à jour de compatibilité et cible désormais le SDK 36 (Android 16). De plus, il est maintenant possible de configurer un proxy HTTP et de sélectionner des certificats utilisateurs dans les profils gérés (Work Profiles).

# Semaine du 06/10/2025 au 12/10/2025
## Nouveautés pour le plugin VICI
Les développeurs utilisant les liaisons Python du plugin VICI bénéficient de nouveaux décorateurs qui simplifient grandement l'écoute et la gestion des événements asynchrones. La gestion des déconnexions volontaires a également été clarifiée.

# Semaine du 11/08/2025 au 17/08/2025
## Versions des plugins
L'architecture des plugins a été améliorée avec l'introduction d'un système de versionnement explicite. Chaque plugin déclare désormais sa version, qui est vérifiée lors de son chargement.

# Semaine du 04/08/2025 au 10/08/2025
## Évolutions cryptographiques OpenSSL
L'intégration d'OpenSSL a été enrichie avec l'ajout du support tant attendu des clés Ed25519 (via AWS-LC) et des clés EdDSA dans les conteneurs PKCS#12, modernisant ainsi les algorithmes supportés par le projet.

# Semaine du 14/07/2025 au 20/07/2025
## Améliorations de WolfSSL
Le plugin WolfSSL intègre de nouvelles optimisations pour se conformer au mode FIPS. Il permet également de configurer et stocker le générateur de nombres aléatoires spécifiquement pour la courbe 25519.

# Semaine du 02/06/2025 au 08/06/2025
## Support du proxy pour l'application Android
Introduction complète du support de proxy HTTP pour l'application Android. Les paramètres du proxy peuvent être configurés manuellement, importés via les profils VPN, ou gérés de manière centralisée par une solution MDM.
