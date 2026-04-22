# Analyse des Vulnérabilités (CVE) Corrigées dans Strongswan 6.0.6

Ce document détaille l'analyse technique des vulnérabilités de sécurité corrigées entre la version 6.0.5 et 6.0.6 de strongSwan. Pour chaque CVE, nous expliquons le défaut présent dans le code, le risque inhérent, les cas de figure qui exposent un utilisateur au risque, ainsi que des pistes de mitigation.

## CVE-2026-35328 : Déni de service par boucle infinie dans `libtls`

**Description et Risque (Vulnérabilité) :**
Dans le composant serveur de `libtls` (implémentation TLS de strongSwan), lors du traitement du message `ClientHello`, le code itère sur l'extension `supported_versions`. L'ancienne implémentation utilisait la fonction `remaining()` du `bio_reader` combinée à la lecture de blocs de 2 octets (`read_uint16`). Cependant, si un attaquant envoie une extension dont la taille totale est impaire (non multiple de 2), `read_uint16` échoue à lire les derniers octets (sans faire avancer le curseur de fin de boucle), tandis que `remaining()` continue de retourner `TRUE`. Cela provoque une boucle infinie où le thread se retrouve bloqué indéfiniment. Un attaquant initiant plusieurs connexions avec ces extensions malformées peut rapidement monopoliser tous les threads disponibles, empêchant le traitement d'autres paquets IKE/TLS, ce qui caractérise une attaque par Déni de Service (DoS).

**Utilisateurs à risque :**
Les utilisateurs vulnérables sont ceux dont les configurations strongSwan utilisent l'implémentation TLS intégrée pour authentifier les pairs. Cela concerne particulièrement les passerelles qui proposent des méthodes d'authentification EAP basées sur TLS (comme EAP-TLS, EAP-PEAP ou EAP-TTLS). Les tunnels IKEv2 classiques par clés pré-partagées ou certificats simples ne sont pas impactés.

**Recommandations et Mitigations :**
- **Désactiver les méthodes EAP-TLS/PEAP/TTLS** si elles ne sont pas strictement nécessaires.
- Limiter l'accès aux ports IKE (UDP 500/4500) via des pare-feux pour n'accepter que les adresses IP de clients connus.

---

## CVE-2026-35329 : Crash via Déréférencement de Pointeur Nul dans `pkcs7` / `pkcs5`

**Description et Risque (Vulnérabilité) :**
Le code qui vérifie la taille du padding pour les données enveloppées (chiffrées) PKCS#7 et PKCS#5 dans libstrongswan manquait de validation sur la longueur des données déchiffrées. Si les données reçues (`blob->len` ou `this->content.len`) ont une longueur de 0, le code essaie d'accéder à l'octet situé à l'index `longueur - 1` pour déterminer le motif de padding. Ce comportement entraîne un déréférencement de pointeur invalide ou nul, causant immédiatement le crash du processus `charon` par segmentation fault (SIGSEGV).

**Utilisateurs à risque :**
Tout utilisateur exposant IKEv1 ou IKEv2 et acceptant des payloads de certificats (CERT payloads). Un attaquant non authentifié peut envoyer des conteneurs PKCS#7 chiffrés vides lors de l'échange de messages initial (particulièrement en IKEv1) pour provoquer le crash du démon, constituant ainsi un risque important de Déni de Service (DoS).

**Recommandations et Mitigations :**
- **Désactiver IKEv1** : Ce protocole est obsolète et plus enclin à exposer ce type d'échanges au début de la négociation.
- Si IKEv2 est utilisé avec des certificats, le risque est légèrement moindre mais toujours présent. La mise à jour est vivement recommandée. Désactiver le plugin `pkcs7` si les certificats enveloppés ne sont pas nécessaires à l'architecture.

---

## CVE-2026-35330 : Exécution de code à distance (RCE) / Buffer Overflow dans `libsimaka`

**Description et Risque (Vulnérabilité) :**
Dans la librairie `libsimaka`, responsable de l'analyse des messages EAP-SIM et EAP-AKA, la fonction `parse_attributes` calcule la taille utile des attributs en soustrayant la taille de l'en-tête (typiquement 4 octets) à la longueur annoncée par cet en-tête. Or, si l'attribut a une longueur annoncée de 0, la multiplication par 4 donne 0. Le test (`hdr->length * 4 > in.len`) passe, puis le code effectue la soustraction `(0 - 4)`, provoquant un "integer underflow" (dépassement d'entier vers une valeur très grande). Cette taille aberrante est ensuite passée à `add_attribute()`, ce qui conduit à écrire au-delà d'un tampon alloué sur le tas (heap-based buffer overflow). Cela permet à un attaquant non seulement de crasher le service (DoS), mais potentiellement d'exécuter du code arbitraire à distance (RCE). Dans le cas de l'attribut `AT_PADDING`, cela peut engendrer une boucle infinie.

**Utilisateurs à risque :**
Cette faille est critique pour les déploiements (souvent dans les réseaux télécoms) utilisant strongSwan pour authentifier des appareils mobiles via l'EAP-SIM ou l'EAP-AKA. Tout serveur exposant ces méthodes via IKEv2 ou RADIUS est très fortement exposé.

**Recommandations et Mitigations :**
- **Désactiver les plugins EAP-SIM, EAP-AKA et EAP-AKA-3GPP2** (`eap-sim`, `eap-aka`, etc.) si vous n'avez pas de clients télécom requérant l'usage de cartes SIM pour s'authentifier.
- Restreindre très sévèrement l'accès IKE.

---

## CVE-2026-35331 : Contournement des contraintes d'identité X.509 (Name Constraints)

**Description et Risque (Vulnérabilité) :**
Le plugin `constraints` vérifie que les certificats fournis par les pairs respectent certaines contraintes de nom ("Name Constraints") imposées par une autorité de certification (CA). La vulnérabilité réside dans le fait que les contraintes exclues ("excluded name constraints", pour FQDN, email, et DirectoryName) étaient comparées de manière stricte et binaire ou n'étaient pas correctement gérées pour la casse. Par conséquent, une autorité de certification intermédiaire malveillante ou compromise pourrait émettre un certificat valide contournant une contrainte d'exclusion en modifiant simplement la casse (par exemple `strongSwan.org` au lieu de `strongswan.org`). Pour les types `directoryName` (DN), la complexité (notamment pour l'UTF8String) empêchait une comparaison sûre ; le patch modifie donc le comportement pour rejeter catégoriquement tout certificat contenant des contraintes d'exclusion de type DN.

**Utilisateurs à risque :**
Les passerelles VPN configurées pour utiliser le plugin `constraints` et s'appuyant sur des PKI (Public Key Infrastructures) complexes avec des CAs intermédiaires limitées par des "Excluded Name Constraints". Le risque est que des utilisateurs illégitimes obtiennent un accès au réseau VPN.

**Recommandations et Mitigations :**
- Préférer l'usage de contraintes permises ("Permitted Name Constraints") plutôt que des contraintes exclues, qui sont notoirement difficiles à maintenir de façon exhaustive et sécurisée.
- Limiter strictement les autorités de certification (CA) intermédiaires en qui vous avez confiance.

---

## CVE-2026-35332 : Crash par clé publique ECDH vide dans `libtls` (TLS < 1.3)

**Description et Risque (Vulnérabilité) :**
Dans le serveur TLS embarqué, la lecture de la clé publique ECDH (`ClientKeyExchange`) pour des versions TLS antérieures à 1.3 souffrait d'un oubli dans les contrôles de taille pour le cas des courbes elliptiques (`ec`). Si un enregistrement TLS malveillant se terminait par un `ClientKeyExchange` de taille nulle, la variable pointant sur la clé était retournée vide. Le code tentait ensuite d'accéder au premier octet de cette clé vide (`pub.ptr[0]`), menant à un déréférencement de pointeur nul et provoquant le crash immédiat du démon.

**Utilisateurs à risque :**
Idem que pour la CVE-2026-35328 : les installations utilisant des méthodes d'authentification basées sur l'implémentation TLS interne de strongSwan (EAP-TLS, EAP-PEAP, EAP-TTLS). L'attaquant n'a pas besoin de s'authentifier.

**Recommandations et Mitigations :**
- Forcer l'utilisation stricte de TLS 1.3, car la faille cible le processus d'échange de clés des anciennes versions TLS (< 1.3).
- Alternativement, désactiver les méthodes EAP basées sur TLS si vous pouvez vous rabattre sur des clés IKE classiques ou des certificats directs IKEv2.

---

## CVE-2026-35333 : Boucle infinie dans l'itération des attributs `libradius`

**Description et Risque (Vulnérabilité) :**
Dans `libradius`, la fonction d'itération `attribute_enumerate()` traitant les paquets RADIUS ne vérifiait pas si la longueur d'un attribut reçu (encodée dans son en-tête d'un octet) était inférieure à la taille minimale requise pour un attribut RADIUS (2 octets : le type et la taille). Si la longueur reçue est de 0, l'itérateur n'avance jamais dans le tampon réseau, emprisonnant le thread dans une boucle infinie non bloquante. Si la longueur est de 1, cela crée des accès mémoire mal alignés sur des structures packées. Cela permet à un serveur RADIUS malveillant (ou compromis), ou via une attaque de type "Man-In-The-Middle" si le flux RADIUS n'est pas sécurisé, de figer indéfiniment les threads d'authentification de strongSwan.

**Utilisateurs à risque :**
Les passerelles IKE configurées pour déléguer l'authentification des utilisateurs (via EAP, par exemple XAuth ou EAP-Radius) à un serveur RADIUS externe, c'est-à-dire celles utilisant le plugin `eap-radius`.

**Recommandations et Mitigations :**
- S'assurer que le trafic entre la passerelle strongSwan et le serveur RADIUS est hautement sécurisé et s'effectue sur un réseau de confiance inviolable ou via un tunnel IPSec dédié (pour prévenir les usurpations/MITM).
- Mettre à jour au plus vite.

---

## CVE-2026-35334 : Fuites temporelles (Timing Leaks) et crash dans le plugin `gmp` (RSA)

**Description et Risque (Vulnérabilité) :**
L'implémentation de déchiffrement RSA dans le plugin mathématique `gmp` était doublement vulnérable. Premièrement, le code ne vérifiait pas si la sortie de la fonction de bas niveau `rsadp()` était nulle (ce qui peut arriver avec un message chiffré contenant que des zéros), entraînant un crash par déréférencement nul. Deuxièmement, la validation du padding pour le déchiffrement PKCS#1 v1.5 n'était pas effectuée en temps constant (constant-time). Cette fuite temporelle (~17.5 μs) permet théoriquement une attaque du type Bleichenbacher pour déchiffrer des messages ou forger des signatures si l'attaquant peut envoyer un très grand nombre de messages et mesurer la réponse.

**Utilisateurs à risque :**
Le risque réel en production est très limité, pour deux raisons majeures :
1. Les messages TLS (les plus sensibles à l'attaque de Bleichenbacher) sont encapsulés dans EAP, lui-même encapsulé dans un tunnel IKE chiffré ; ce qui bloque une exploitation de masse nécessaire pour l'attaque.
2. Le plugin `gmp` n'est plus le plugin de cryptographie actif par défaut. L'immense majorité des déploiements utilise le plugin `openssl`, `wolfssl` ou `botan` pour les opérations cryptographiques RSA.
Les utilisateurs à risque sont donc ceux qui ont explicitement forcé l'utilisation du plugin `gmp` comme backend cryptographique principal pour RSA.

**Recommandations et Mitigations :**
- **Désactiver le plugin `gmp`** dans la configuration strongSwan (`--disable-gmp`) et privilégier l'utilisation du plugin `openssl` (activé par défaut) ou `gcrypt` qui bénéficient d'implémentations robustes aux attaques temporelles.
