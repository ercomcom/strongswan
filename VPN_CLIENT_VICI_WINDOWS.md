# Documentation technique : Contrôle d'un client VPN Strongswan via VICI sous Windows

Cette documentation détaille l'utilisation du protocole **VICI** (Versatile IKE Configuration Interface) pour configurer et contrôler une instance embarquée de Strongswan depuis une IHM Windows.

L'objectif principal est de démontrer que VICI n'est pas limité à la simple consultation d'état, mais qu'il offre un contrôle exhaustif du cycle de vie du VPN (configuration, authentification, démarrage, arrêt), tout en offrant des mécanismes d'extension pour communiquer avec des composants métiers spécifiques.

---

## 1. Introduction à VICI

VICI est le protocole de gestion moderne de Strongswan. Il remplace avantageusement l'ancienne interface `stroke`.
Il est basé sur des échanges de messages binaires (type clé/valeur, listes, sections) transportés sur un flux réseau.

Dans le contexte d'une application Windows où Strongswan tourne dans le même processus (compilé sous forme de librairies comme `libcharon` / `libstrongswan`), le plugin **`vici`** de Strongswan expose une interface réseau pour recevoir des requêtes.

### 1.1 Transport de VICI sous Windows

Par défaut sous UNIX, VICI utilise une socket de domaine UNIX (ex: `unix:///var/run/charon.vici`).
Sous Windows, les *Unix Domain Sockets* n'étant pas natives historiquement, Strongswan utilise par défaut des sockets TCP pour exposer VICI.
La configuration par défaut définie dans le code source de Strongswan pour Windows est :
`tcp://127.0.0.1:4502`

Il est tout à fait possible de configurer Strongswan pour utiliser d'autres moyens de transport locaux (comme des *Named Pipes*) selon les plugins disponibles, mais une socket TCP locale (`127.0.0.1`) permet une implémentation immédiate et fiable pour la communication entre l'IHM et le service VPN interne.

---

### 1.2 Restreindre l'accès à VICI

Une préoccupation courante est la sécurité de l'interface VICI elle-même : est-il possible d'interdire certaines commandes VICI (par exemple, pour empêcher la suppression de configurations, ou interdire `terminate`) ?

En soi, **VICI n'implémente pas de modèle d'autorisation granulaire par commande** ou de filtrage natif (ACL) intégré à son protocole. Toute application capable d'ouvrir la socket TCP VICI et d'envoyer des requêtes valides a les pleins pouvoirs d'administration sur le daemon (elle peut charger, décharger, initier, terminer, etc.).

Pour restreindre ce qui est exposé :
1. **Protection du Transport** : La première ligne de défense est de restreindre l'accès à la socket de communication. Sous Windows, on peut utiliser des *Named Pipes* (qui gèrent des ACL système Windows pour limiter l'accès à certains utilisateurs ou processus) au lieu d'une socket TCP locale, si on souhaite s'assurer que seules les applications privilégiées peuvent envoyer des commandes.
2. **Code Intermédiaire** : S'il est nécessaire d'offrir une API restreinte (par exemple, une IHM qui a *seulement* le droit de lire l'état), l'architecture recommandée consiste à ne **pas** exposer directement VICI à l'IHM non privilégiée. Au lieu de cela, votre "code propre" qui tourne en processus administrateur agit comme un proxy sécurisé : il offre sa propre API (restreinte) à l'IHM, et utilise lui-même VICI en interne pour parler à Strongswan.

---

## 2. Configuration et démarrage du VPN via VICI

L'une des forces de VICI est qu'il permet de faire **bien plus** que la simple consultation d'état. L'IHM n'a pas besoin de manipuler des fichiers de configuration texte (comme `ipsec.conf` ou `swanctl.conf`). Tout peut être poussé en temps réel en mémoire via VICI.

Voici la cinématique typique des messages VICI qu'une IHM devra échanger avec Strongswan pour configurer et démarrer un VPN :

### 2.1 Pousser les accréditations
Avant de définir les connexions, il faut fournir les certificats, clés privées ou secrets partagés (PSK).
- **`load-shared`** : Permet à l'IHM d'envoyer un secret partagé (IKE PSK, EAP secret).
- **`load-cert`** / **`load-key`** : Permet de charger des certificats X.509 et des clés privées brutes en mémoire.
- **Sécurisation des clés privées et Magasin Windows (Certificate Store)** :
  Envoyer une clé privée brute via la commande `load-key` implique que l'IHM doit l'avoir en mémoire. Pour des raisons de sécurité, cela est souvent indésirable. Strongswan gère les "Smartcards" (PKCS#11) et les trousseaux systèmes.
  Pour le magasin Windows, si vous utilisez des plugins natifs ou personnalisés, la clé privée n'a *jamais* besoin d'être exportée vers Strongswan. Dans ce cas :
  1. Le certificat public (sans sa clé privée) peut être poussé via `load-cert`.
  2. Vous n'envoyez **pas** de `load-key`.
  3. Au lieu de cela, on peut utiliser la commande **`load-token`** de VICI (historiquement conçue pour le PKCS#11) en adaptant son usage, ou mieux, lors de la déclaration de la connexion (`load-conn`), préciser que l'authentification se fait via une référence au magasin (ex: en indiquant des paramètres spécifiques d'authentification pris en charge par le plugin d'authentification Windows). Strongswan cherchera alors le certificat dans le magasin local et utilisera l'API Windows (CAPI/CNG) pour signer les payloads IKE, sans jamais manipuler directement la clé privée.
- *(Il existe aussi `clear-creds` pour tout purger lors d'une déconnexion).*

### 2.2 Pousser la configuration IKE/IPsec
Une fois les accréditations en place, l'IHM peut définir la connexion VPN elle-même.
- **`load-conn`** : Ce message reçoit une structure complète décrivant la connexion VPN. L'IHM y précise les adresses du client, l'adresse de la passerelle distante, les algorithmes de chiffrement (proposals IKE/ESP), et les méthodes d'authentification (ex: EAP-MSCHAPv2, PubKey, etc.).
- *(Son pendant, `unload-conn`, permet de supprimer la connexion en mémoire).*

### 2.3 Contrôler la connexion (Démarrage / Arrêt)
La connexion étant configurée en mémoire, elle est prête à être déclenchée :
- **`initiate`** : Message déclenchant l'établissement du tunnel IKE (IKE_SA) et des tunnels enfants (CHILD_SA). On passe simplement le nom de la connexion et l'enfant à démarrer en paramètre.
- **`terminate`** : Commande pour couper brutalement ou proprement le VPN (fermeture de l'IKE_SA).

### 2.4 Gérer l'état et le suivi (Événements)
Pour que l'IHM puisse afficher si le VPN est "Connecté", "En cours..." ou "Échoué", elle ne doit pas interroger en boucle (polling). VICI utilise un système asynchrone d'**Événements** :
- L'IHM envoie une commande spéciale d'enregistrement d'événement (ex: pour l'événement `ike-updown` ou `child-updown`).
- Strongswan pousse alors automatiquement vers l'IHM des messages non sollicités à chaque fois qu'un tunnel monte ou descend.
- Des commandes de requête synchrones existent aussi : `list-sas` (lister les tunnels actifs), `stats`, etc.

---

## 3. Extension de VICI pour les "Codes Propres"

Vous souhaitez également pouvoir utiliser VICI pour envoyer et recevoir des messages destinés à votre propre logique métier qui tournera au-dessus de Strongswan.

**C'est tout à fait possible et prévu par l'architecture de VICI.**

Le cœur du système VICI s'articule autour d'un objet nommé `vici_dispatcher_t`. Ce dispatcher gère la socket réseau, parse les requêtes entrantes, puis fait appel à des *callbacks* enregistrés pour chaque nom de commande.

### 3.1 Architecture avec un Code Métier "Externe" (Non-Plugin)

Il est important de noter que votre "code propre" n'a pas nécessairement besoin d'être compilé comme un plugin Strongswan interne.

Si votre processus englobe Strongswan (vous chargez `libcharon` en tant que librairie dynamique dans votre programme C/C++ personnalisé sous Windows), **votre application complète partage l'espace mémoire de Strongswan**.
Cela signifie que, depuis le code de votre exécutable (au-dessus de Strongswan) :
1. Vous avez accès à l'instance de la librairie (via les objets globaux ou retournés lors de l'initialisation).
2. Vous pouvez récupérer le pointeur vers le plugin VICI chargé et, par extension, obtenir un pointeur vers son `vici_dispatcher_t`.

Ainsi, tout code au sein de votre processus (même en dehors du dossier `plugins` de Strongswan) peut joindre et interagir avec l'API VICI.

### 3.2 Comment enregistrer des commandes personnalisées ?

Que votre code soit un plugin ou simplement le programme englobant, il peut faire appel à l'API du dispatcher (`vici_dispatcher.h`) :

Puisque vos codes "propres" seront développés sous forme de plugins C/C++ chargés par Strongswan (ou initialisés en même temps que la librairie `libcharon`), vous aurez accès au pointeur du dispatcher VICI.

Le prototype dans l'API de Strongswan (`vici_dispatcher.h`) offre la fonction suivante :
```c
void (*manage_command)(vici_dispatcher_t *this, char *name, vici_command_cb_t cb, void *user);
```

**Procédure :**
1. Lors de l'initialisation de votre plugin métier, récupérez l'instance du `vici_dispatcher`.
2. Appelez `manage_command` avec un nom de commande personnalisé. Par exemple : `manage_command(dispatcher, "mon-code-cmd", ma_fonction_callback, NULL);`.
3. Côté IHM, il suffira d'envoyer une requête VICI standard nommée `mon-code-cmd`.
4. Le flux VICI l'interceptera et appellera directement `ma_fonction_callback(void *user, char *name, u_int id, vici_message_t *request)`.
5. Votre code lira les attributs du message et renverra un message de réponse (`vici_message_t*`) que VICI acheminera vers l'IHM.

### 3.3 Envoyer des événements personnalisés

Le système d'événements peut lui aussi être étendu de la même manière :
```c
void (*manage_event)(vici_dispatcher_t *this, char *name, bool reg);
void (*raise_event)(vici_dispatcher_t *this, char *name, u_int id, vici_message_t *message);
```

**Procédure :**
1. Votre plugin enregistre un nouvel événement avec `manage_event(dispatcher, "mon-code-event", TRUE);`.
2. L'IHM s'abonne à "mon-code-event".
3. Au moment opportun, votre code appelle `raise_event` avec les données structurées. L'IHM recevra instantanément cet événement.

---

## 4. Conclusion

L'utilisation du protocole **VICI est un excellent choix technique** pour votre architecture :
1. **Complétude** : VICI permet l'administration intégrale du VPN : configuration (poussée dynamique via `load-conn`, `load-cert`), pilotage (`initiate`, `terminate`) et observation temps-réel (événements).
2. **Transport adapté** : L'utilisation de TCP (`127.0.0.1:4502`) sous Windows est standard et permet une interopérabilité aisée avec n'importe quel langage d'IHM (C#, C++, Python, etc.).
3. **Extensibilité totale** : La conception modulaire de `vici_dispatcher` vous permet de rajouter sans friction vos propres commandes et événements (`manage_command`, `raise_event`) pour que l'IHM discute de façon bidirectionnelle avec vos plugins C/C++ internes à Strongswan, en passant par le même canal de communication.
