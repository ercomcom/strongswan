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

## 2. Configuration et démarrage du VPN via VICI

L'une des forces de VICI est qu'il permet de faire **bien plus** que la simple consultation d'état. L'IHM n'a pas besoin de manipuler des fichiers de configuration texte (comme `ipsec.conf` ou `swanctl.conf`). Tout peut être poussé en temps réel en mémoire via VICI.

Voici la cinématique typique des messages VICI qu'une IHM devra échanger avec Strongswan pour configurer et démarrer un VPN :

### 2.1 Pousser les accréditations
Avant de définir les connexions, il faut fournir les certificats, clés privées ou secrets partagés (PSK).
- **`load-shared`** : Permet à l'IHM d'envoyer un secret partagé (IKE PSK, EAP secret).
- **`load-cert`** / **`load-key`** : Permet de charger des certificats X.509 et des clés privées.
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

Vous souhaitez également pouvoir utiliser VICI pour envoyer et recevoir des messages destinés à votre propre logique métier qui tournera au-dessus de Strongswan, tout en partageant le même processus.

**C'est tout à fait possible et prévu par l'architecture de VICI.**

Le cœur du système VICI s'articule autour d'un objet nommé `vici_dispatcher_t`. Ce dispatcher gère la socket réseau, parse les requêtes entrantes, puis fait appel à des *callbacks* enregistrés pour chaque nom de commande.

Tous les modules standards de Strongswan (ex: `vici_control.c` pour `initiate`, `vici_config.c` pour `load-conn`) enregistrent leurs propres commandes de cette manière. Vous pouvez faire exactement la même chose pour vos plugins !

### 3.1 Comment enregistrer des commandes personnalisées ?

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

### 3.2 Envoyer des événements personnalisés

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
