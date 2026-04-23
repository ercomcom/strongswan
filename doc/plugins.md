# Documentation des Plugins strongSwan

Ce document liste les plugins disponibles dans le projet strongSwan, avec leur rôle, localisation, dépendances et plateformes supportées.

## acert
- **Rôle** : enable X509 attribute certificate checking plugin.
- **Localisation** : `src/libstrongswan/plugins/acert` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon

## addrblock
- **Rôle** : enables RFC 3779 address block constraint support.
- **Localisation** : `src/libcharon/plugins/addrblock` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## aes
- **Rôle** : enable AES software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/aes` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, nm, cmd

## aesni
- **Rôle** : enable Intel AES-NI crypto plugin.
- **Localisation** : `src/libstrongswan/plugins/aesni` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, medsrv, attest, nm, cmd, aikgen

## af_alg
- **Rôle** : enable AF_ALG crypto interface to Linux Crypto API.
- **Localisation** : `src/libstrongswan/plugins/af_alg` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, medsrv, attest, nm, cmd, aikgen

## agent
- **Rôle** : enables the ssh-agent signing plugin.
- **Localisation** : `src/libstrongswan/plugins/agent` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, nm, cmd

## android_dns
- **Rôle** : enable Android specific DNS handler.
- **Localisation** : `src/libcharon/plugins/android_dns` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Android
- **Dépendances** : cutils
- **Composants l'utilisant** : c, charon

## android_log
- **Rôle** : enable Android specific logger plugin.
- **Localisation** : `src/libcharon/plugins/android_log` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Android
- **Dépendances** : log
- **Composants l'utilisant** : c, charon

## attr
- **Rôle** : disable strongswan.conf based configuration attribute plugin.
- **Localisation** : `src/libcharon/plugins/attr` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## attr_sql
- **Rôle** : enable SQL based configuration attribute plugin.
- **Localisation** : `src/libcharon/plugins/attr_sql` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## blowfish
- **Rôle** : enable Blowfish software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/blowfish` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, nm, cmd

## botan
- **Rôle** : enables the Botan crypto plugin.
- **Localisation** : `src/libstrongswan/plugins/botan` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : botan_LIBS
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd, aikgen

## bypass_lan
- **Rôle** : enable plugin to install bypass policies for local subnets.
- **Localisation** : `src/libcharon/plugins/bypass_lan` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## ccm
- **Rôle** : enables the CCM AEAD wrapper crypto plugin.
- **Localisation** : `src/libstrongswan/plugins/ccm` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, scripts, nm, cmd

## certexpire
- **Rôle** : enable CSV export of expiration dates of used certificates.
- **Localisation** : `src/libcharon/plugins/certexpire` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## chapoly
- **Rôle** : enables the ChaCha20/Poly1305 AEAD plugin.
- **Localisation** : `src/libstrongswan/plugins/chapoly` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, scripts, nm, cmd

## cmac
- **Rôle** : disable CMAC crypto implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/cmac` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, nm, cmd

## connmark
- **Rôle** : enable connmark plugin using conntrack based marks to select return path SA.
- **Localisation** : `src/libcharon/plugins/connmark` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : libiptc_LIBS
- **Composants l'utilisant** : c, charon

## constraints
- **Rôle** : disable advanced X509 constraint checking plugin.
- **Localisation** : `src/libstrongswan/plugins/constraints` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, pki, nm, cmd

## counters
- **Rôle** : enable plugin that collects several performance counters.
- **Localisation** : `src/libcharon/plugins/counters` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## coupling
- **Rôle** : enable IKEv2 plugin to couple peer certificates permanently to authentication.
- **Localisation** : `src/libcharon/plugins/coupling` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## ctr
- **Rôle** : enables the Counter Mode wrapper crypto plugin.
- **Localisation** : `src/libstrongswan/plugins/ctr` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, scripts, nm, cmd

## curl
- **Rôle** : enable CURL fetcher plugin to fetch files via libcurl. Requires libcurl.
- **Localisation** : `src/libstrongswan/plugins/curl` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : curl
- **Composants l'utilisant** : s, charon, pki, scripts, nm, cmd

## curve25519
- **Rôle** : enable Curve25519 Diffie-Hellman plugin.
- **Localisation** : `src/libstrongswan/plugins/curve25519` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, nm, cmd

## des
- **Rôle** : enable DES/3DES software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/des` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, nm, cmd

## dhcp
- **Rôle** : enable DHCP based attribute provider plugin.
- **Localisation** : `src/libcharon/plugins/dhcp` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## dnscert
- **Rôle** : enable DNSCERT authentication plugin.
- **Localisation** : `src/libcharon/plugins/dnscert` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## dnskey
- **Rôle** : disable DNS RR key decoding plugin.
- **Localisation** : `src/libstrongswan/plugins/dnskey` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki

## drbg
- **Rôle** : disable the NIST Deterministic Random Bit Generator plugin.
- **Localisation** : `src/libstrongswan/plugins/drbg` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, nm, cmd

## duplicheck
- **Rôle** : advanced duplicate checking plugin using liveness checks.
- **Localisation** : `src/libcharon/plugins/duplicheck` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_aka
- **Rôle** : enable EAP AKA authentication module.
- **Localisation** : `src/libcharon/plugins/eap_aka` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_aka_3gpp
- **Rôle** : enable EAP AKA backend implementing 3GPP MILENAGE algorithms in software.
- **Localisation** : `src/libcharon/plugins/eap_aka_3gpp` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_aka_3gpp2
- **Rôle** : enable EAP AKA backend implementing 3GPP2 algorithms in software. Requires libgmp.
- **Localisation** : `src/libcharon/plugins/eap_aka_3gpp2` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : gmp
- **Composants l'utilisant** : c, charon

## eap_dynamic
- **Rôle** : enable dynamic EAP proxy module.
- **Localisation** : `src/libcharon/plugins/eap_dynamic` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_gtc
- **Rôle** : enable EAP GTC authentication module.
- **Localisation** : `src/libcharon/plugins/eap_gtc` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## eap_identity
- **Rôle** : enable EAP module providing EAP-Identity helper.
- **Localisation** : `src/libcharon/plugins/eap_identity` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## eap_md5
- **Rôle** : enable EAP MD5 (CHAP) authentication module.
- **Localisation** : `src/libcharon/plugins/eap_md5` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## eap_mschapv2
- **Rôle** : enable EAP MS-CHAPv2 authentication module.
- **Localisation** : `src/libcharon/plugins/eap_mschapv2` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## eap_peap
- **Rôle** : enable EAP PEAP authentication module.
- **Localisation** : `src/libcharon/plugins/eap_peap` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## eap_radius
- **Rôle** : enable RADIUS proxy authentication module.
- **Localisation** : `src/libcharon/plugins/eap_radius` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_sim
- **Rôle** : enable SIM authentication module for EAP.
- **Localisation** : `src/libcharon/plugins/eap_sim` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_sim_file
- **Rôle** : enable EAP-SIM backend based on a triplet file.
- **Localisation** : `src/libcharon/plugins/eap_sim_file` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_sim_pcsc
- **Rôle** : enable EAP-SIM backend based on a smartcard reader. Requires libpcsclite.
- **Localisation** : `src/libcharon/plugins/eap_sim_pcsc` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : {pcsclite_LIBS}
- **Composants l'utilisant** : c, charon

## eap_simaka_pseudonym
- **Rôle** : enable EAP-SIM/AKA pseudonym storage plugin.
- **Localisation** : `src/libcharon/plugins/eap_simaka_pseudonym` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_simaka_reauth
- **Rôle** : enable EAP-SIM/AKA reauthentication data storage plugin.
- **Localisation** : `src/libcharon/plugins/eap_simaka_reauth` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_simaka_sql
- **Rôle** : enable EAP-SIM/AKA backend based on a triplet/quintuplet SQL database.
- **Localisation** : `src/libcharon/plugins/eap_simaka_sql` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_tls
- **Rôle** : enable EAP TLS authentication module.
- **Localisation** : `src/libcharon/plugins/eap_tls` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## eap_tnc
- **Rôle** : enable EAP TNC trusted network connect module.
- **Localisation** : `src/libcharon/plugins/eap_tnc` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## eap_ttls
- **Rôle** : enable EAP TTLS authentication module.
- **Localisation** : `src/libcharon/plugins/eap_ttls` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## error_notify
- **Rôle** : enable error notification plugin.
- **Localisation** : `src/libcharon/plugins/error_notify` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## ext_auth
- **Rôle** : enable plugin calling an external authorization script.
- **Localisation** : `src/libcharon/plugins/ext_auth` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## farp
- **Rôle** : enable ARP faking plugin that responds to ARP requests to peers virtual IP
- **Localisation** : `src/libcharon/plugins/farp` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## files
- **Rôle** : enable simple file:// URI fetcher.
- **Localisation** : `src/libstrongswan/plugins/files` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, pki, scripts, nm, cmd

## fips_prf
- **Rôle** : enable FIPS PRF software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/fips_prf` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, nm, cmd

## forecast
- **Rôle** : enable forecast plugin forwarding broadcast/multicast messages.
- **Localisation** : `src/libcharon/plugins/forecast` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : libiptc_LIBS
- **Composants l'utilisant** : c, charon

## gcm
- **Rôle** : enable the GCM AEAD wrapper crypto plugin.
- **Localisation** : `src/libstrongswan/plugins/gcm` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, scripts, nm, cmd

## gcrypt
- **Rôle** : enables the libgcrypt plugin.
- **Localisation** : `src/libstrongswan/plugins/gcrypt` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : gcrypt, gpg-error
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd, aikgen

## gmp
- **Rôle** : enable GNU MP (libgmp) based crypto implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/gmp` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : gmp
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd, aikgen, fc

## ha
- **Rôle** : enable high availability cluster plugin.
- **Localisation** : `src/libcharon/plugins/ha` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## hmac
- **Rôle** : enable HMAC crypto implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/hmac` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, nm, cmd

## imc_attestation
- **Rôle** : enable IMC attestation module.
- **Localisation** : `src/libimcv/plugins/imc_attestation` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imc_hcd
- **Rôle** : enable IMC hcd module.
- **Localisation** : `src/libimcv/plugins/imc_hcd` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imc_os
- **Rôle** : enable IMC operating system module.
- **Localisation** : `src/libimcv/plugins/imc_os` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imc_scanner
- **Rôle** : enable IMC port scanner module.
- **Localisation** : `src/libimcv/plugins/imc_scanner` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imc_swima
- **Rôle** : enable IMC swima module.
- **Localisation** : `src/libimcv/plugins/imc_swima` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imc_test
- **Rôle** : enable IMC test module.
- **Localisation** : `src/libimcv/plugins/imc_test` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imv_attestation
- **Rôle** : enable IMV attestation module.
- **Localisation** : `src/libimcv/plugins/imv_attestation` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imv_hcd
- **Rôle** : enable IMV hcd module.
- **Localisation** : `src/libimcv/plugins/imv_hcd` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imv_os
- **Rôle** : enable IMV operating system module.
- **Localisation** : `src/libimcv/plugins/imv_os` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imv_scanner
- **Rôle** : enable IMV port scanner module.
- **Localisation** : `src/libimcv/plugins/imv_scanner` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imv_swima
- **Rôle** : enable IMV swima module.
- **Localisation** : `src/libimcv/plugins/imv_swima` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## imv_test
- **Rôle** : enable IMV test module.
- **Localisation** : `src/libimcv/plugins/imv_test` (Bibliothèque : `libimcv`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)

## ipseckey
- **Rôle** : enable IPSECKEY authentication plugin.
- **Localisation** : `src/libcharon/plugins/ipseckey` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## kdf
- **Rôle** : disable KDF (prf+) implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/kdf` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, nm, cmd

## kernel_iph
- **Rôle** : enable the Windows IP Helper based networking backend.
- **Localisation** : `src/libcharon/plugins/kernel_iph` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Windows
- **Dépendances** : iphlpapi
- **Composants l'utilisant** : c, charon

## kernel_libipsec
- **Rôle** : enable the libipsec kernel interface.
- **Localisation** : `src/libcharon/plugins/kernel_libipsec` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, cmd

## kernel_netlink
- **Rôle** : disable the netlink kernel interface.
- **Localisation** : `src/libcharon/plugins/kernel_netlink` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : DLLIB
- **Composants l'utilisant** : c, charon, nm, cmd

## kernel_pfkey
- **Rôle** : enable the PF_KEY kernel interface.
- **Localisation** : `src/libcharon/plugins/kernel_pfkey` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## kernel_pfroute
- **Rôle** : enable the PF_ROUTE kernel interface.
- **Localisation** : `src/libcharon/plugins/kernel_pfroute` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## kernel_wfp
- **Rôle** : enable the Windows Filtering Platform IPsec backend.
- **Localisation** : `src/libcharon/plugins/kernel_wfp` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Windows
- **Dépendances** : fwpuclnt
- **Composants l'utilisant** : c, charon

## keychain
- **Rôle** : enables OS X Keychain Services credential set.
- **Localisation** : `src/libstrongswan/plugins/keychain` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, cmd

## ldap
- **Rôle** : enable LDAP fetching plugin to fetch files via libldap. Requires openLDAP.
- **Localisation** : `src/libstrongswan/plugins/ldap` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : lber, ldap
- **Composants l'utilisant** : s, charon, pki, scripts, nm, cmd

## led
- **Rôle** : enable plugin to control LEDs on IKEv2 activity using the Linux kernel LED subsystem.
- **Localisation** : `src/libcharon/plugins/led` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## load_tester
- **Rôle** : enable load testing plugin for IKEv2 daemon.
- **Localisation** : `src/libcharon/plugins/load_tester` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## lookip
- **Rôle** : enable fast virtual IP lookup and notification plugin.
- **Localisation** : `src/libcharon/plugins/lookip` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## md4
- **Rôle** : enable MD4 software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/md4` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, nm, cmd

## md5
- **Rôle** : enable MD5 software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/md5` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, attest, nm, cmd, aikgen

## medcli
- **Rôle** : enable mediation client configuration database plugin.
- **Localisation** : `src/libcharon/plugins/medcli` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## medsrv
- **Rôle** : enable mediation server web frontend and daemon plugin.
- **Localisation** : `src/libcharon/plugins/medsrv` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## mgf1
- **Rôle** : enable the MGF1 software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/mgf1` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, medsrv, attest, nm, cmd, aikgen, fc

## ml
- **Rôle** : enable Module-Lattice-based crypto (ML-KEM) plugin.
- **Localisation** : `src/libstrongswan/plugins/ml` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, scripts, nm, cmd

## mysql
- **Rôle** : enable MySQL database support. Requires libmysqlclient_r.
- **Localisation** : `src/libstrongswan/plugins/mysql` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : MYSQLLIB
- **Composants l'utilisant** : s, charon, pki, pool, manager, medsrv, attest

## nonce
- **Rôle** : disable nonce generation plugin.
- **Localisation** : `src/libstrongswan/plugins/nonce` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, nm, cmd, aikgen

## openssl
- **Rôle** : disable the OpenSSL crypto plugin.
- **Localisation** : `src/libstrongswan/plugins/openssl` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : OPENSSL_LIB
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd, aikgen, fd

## openxpki
- **Rôle** : enable OCSP responder accessing OpenXPKI certificate database.
- **Localisation** : `src/libstrongswan/plugins/openxpki` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, pki

## osx_attr
- **Rôle** : enable OS X SystemConfiguration attribute handler.
- **Localisation** : `src/libcharon/plugins/osx_attr` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : macOS
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, cmd

## p_cscf
- **Rôle** : enable plugin to request P-CSCF server addresses from an ePDG.
- **Localisation** : `src/libcharon/plugins/p_cscf` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, cmd

## padlock
- **Rôle** : enables VIA Padlock crypto plugin.
- **Localisation** : `src/libstrongswan/plugins/padlock` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon

## pem
- **Rôle** : disable PEM decoding plugin.
- **Localisation** : `src/libstrongswan/plugins/pem` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd, aikgen, fd, fc

## pgp
- **Rôle** : disable PGP key decoding plugin.
- **Localisation** : `src/libstrongswan/plugins/pgp` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon

## pkcs1
- **Rôle** : disable PKCS1 key decoding plugin.
- **Localisation** : `src/libstrongswan/plugins/pkcs1` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd, aikgen, fd, fc

## pkcs11
- **Rôle** : enables the PKCS11 token support plugin.
- **Localisation** : `src/libstrongswan/plugins/pkcs11` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, pki, nm, cmd

## pkcs12
- **Rôle** : enable PKCS12 container support plugin.
- **Localisation** : `src/libstrongswan/plugins/pkcs12` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, cmd

## pkcs7
- **Rôle** : disable PKCS7 container support plugin.
- **Localisation** : `src/libstrongswan/plugins/pkcs7` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, nm, cmd

## pkcs8
- **Rôle** : disable PKCS8 private key decoding plugin.
- **Localisation** : `src/libstrongswan/plugins/pkcs8` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd

## pubkey
- **Rôle** : disable RAW public key support plugin.
- **Localisation** : `src/libstrongswan/plugins/pubkey` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, cmd, aikgen

## radattr
- **Rôle** : enable plugin to inject and process custom RADIUS attributes as IKEv2 client.
- **Localisation** : `src/libcharon/plugins/radattr` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## random
- **Rôle** : disable RNG implementation on top of /dev/(u)random.
- **Localisation** : `src/libstrongswan/plugins/random` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd, aikgen

## rc2
- **Rôle** : enable RC2 software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/rc2` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, nm, cmd

## rdrand
- **Rôle** : enable Intel RDRAND random generator plugin.
- **Localisation** : `src/libstrongswan/plugins/rdrand` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, medsrv, attest, nm, cmd, aikgen

## resolve
- **Rôle** : disable resolve DNS handler plugin.
- **Localisation** : `src/libcharon/plugins/resolve` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, cmd

## revocation
- **Rôle** : disable X509 CRL/OCSP revocation check plugin.
- **Localisation** : `src/libstrongswan/plugins/revocation` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, pki, nm, cmd

## save_keys
- **Rôle** : enable development/debugging plugin that saves IKE and ESP keys in Wireshark format.
- **Localisation** : `src/libcharon/plugins/save_keys` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c

## selinux
- **Rôle** : enable SELinux support for labeled IPsec.
- **Localisation** : `src/libcharon/plugins/selinux` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## sha1
- **Rôle** : enable SHA1 software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/sha1` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd, aikgen, fc

## sha2
- **Rôle** : enable SHA256/SHA384/SHA512 software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/sha2` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, medsrv, attest, nm, cmd, aikgen, fc

## sha3
- **Rôle** : enable SHA3_224/SHA3_256/SHA3_384/SHA3_512 software implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/sha3` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, medsrv, attest, nm, cmd, aikgen, fc

## smp
- **Rôle** : enable SMP configuration and control interface. Requires libxml.
- **Localisation** : `src/libcharon/plugins/smp` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : {xml_LIBS}
- **Composants l'utilisant** : c, charon

## socket_default
- **Rôle** : disable default socket implementation for charon.
- **Localisation** : `src/libcharon/plugins/socket_default` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, nm, cmd

## socket_dynamic
- **Rôle** : enable dynamic socket implementation for charon
- **Localisation** : `src/libcharon/plugins/socket_dynamic` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, cmd

## socket_win
- **Rôle** : enable Winsock2 based socket implementation for charon
- **Localisation** : `src/libcharon/plugins/socket_win` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : ws2_32
- **Composants l'utilisant** : c, charon

## soup
- **Rôle** : enable soup fetcher plugin to fetch from HTTP via libsoup. Requires libsoup.
- **Localisation** : `src/libstrongswan/plugins/soup` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : {soup_LIBS}
- **Composants l'utilisant** : s, charon, pki, scripts, nm, cmd

## sql
- **Rôle** : enable SQL database configuration backend.
- **Localisation** : `src/libcharon/plugins/sql` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## sqlite
- **Rôle** : enable SQLite database support. Requires libsqlite3.
- **Localisation** : `src/libstrongswan/plugins/sqlite` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : sqlite3
- **Composants l'utilisant** : s, charon, pki, pool, manager, medsrv, attest

## sshkey
- **Rôle** : disable SSH key decoding plugin.
- **Localisation** : `src/libstrongswan/plugins/sshkey` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, nm, cmd

## stroke
- **Rôle** : enable the stroke configuration backend.
- **Localisation** : `src/libcharon/plugins/stroke` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## systime_fix
- **Rôle** : enable plugin to handle cert lifetimes with invalid system time gracefully.
- **Localisation** : `src/libcharon/plugins/systime_fix` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## test_vectors
- **Rôle** : enable plugin providing crypto test vectors.
- **Localisation** : `src/libstrongswan/plugins/test_vectors` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki

## tnc_ifmap
- **Rôle** : enable TNC IF-MAP module. Requires libxml
- **Localisation** : `src/libcharon/plugins/tnc_ifmap` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## tnc_imc
- **Rôle** : enable TNC IMC module.
- **Localisation** : `src/libtnccs/plugins/tnc_imc` (Bibliothèque : `libtnccs`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : t, charon

## tnc_imv
- **Rôle** : enable TNC IMV module.
- **Localisation** : `src/libtnccs/plugins/tnc_imv` (Bibliothèque : `libtnccs`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : t, charon

## tnc_pdp
- **Rôle** : enable TNC policy decision point module.
- **Localisation** : `src/libcharon/plugins/tnc_pdp` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## tnc_tnccs
- **Rôle** : Non défini dans configure.ac
- **Localisation** : `src/libtnccs/plugins/tnc_tnccs` (Bibliothèque : `libtnccs`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : t, charon

## tnccs_11
- **Rôle** : enable TNCCS 1.1 protocol module. Requires libxml
- **Localisation** : `src/libtnccs/plugins/tnccs_11` (Bibliothèque : `libtnccs`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : {xml_LIBS}
- **Composants l'utilisant** : t, charon

## tnccs_20
- **Rôle** : enable TNCCS 2.0 protocol module.
- **Localisation** : `src/libtnccs/plugins/tnccs_20` (Bibliothèque : `libtnccs`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : t, charon

## tnccs_dynamic
- **Rôle** : enable dynamic TNCCS protocol discovery module.
- **Localisation** : `src/libtnccs/plugins/tnccs_dynamic` (Bibliothèque : `libtnccs`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : t, charon

## tpm
- **Rôle** : enables the TPM plugin to access private keys and certificates bound to a TPM 2.0.
- **Localisation** : `src/libtpmtss/plugins/tpm` (Bibliothèque : `libtpmtss`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : p, charon, pki, nm, cmd

## unbound
- **Rôle** : enable UNBOUND resolver plugin to perform DNS queries via libunbound. Requires libldns and libunbound.
- **Localisation** : `src/libstrongswan/plugins/unbound` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : unbound, ldns
- **Composants l'utilisant** : s, charon, scripts

## unity
- **Rôle** : enables Cisco Unity extension plugin.
- **Localisation** : `src/libcharon/plugins/unity` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## updown
- **Rôle** : disable updown firewall script plugin.
- **Localisation** : `src/libcharon/plugins/updown` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## vici
- **Rôle** : disable strongSwan IKE generic IPC interface plugin.
- **Localisation** : `src/libcharon/plugins/vici` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## whitelist
- **Rôle** : enable peer identity whitelisting plugin.
- **Localisation** : `src/libcharon/plugins/whitelist` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## winhttp
- **Rôle** : enable WinHTTP based HTTP/HTTPS fetching plugin.
- **Localisation** : `src/libstrongswan/plugins/winhttp` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : winhttp
- **Composants l'utilisant** : s, charon, pki, scripts

## wolfssl
- **Rôle** : enables the wolfSSL crypto plugin.
- **Localisation** : `src/libstrongswan/plugins/wolfssl` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : wolfssl_LIBS
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, manager, medsrv, attest, nm, cmd, aikgen

## x509
- **Rôle** : disable X509 certificate implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/x509` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, swanctl, pki, scripts, attest, nm, cmd, aikgen, fd, fc

## xauth_eap
- **Rôle** : enable XAuth backend using EAP methods to verify passwords.
- **Localisation** : `src/libcharon/plugins/xauth_eap` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## xauth_generic
- **Rôle** : disable generic XAuth backend.
- **Localisation** : `src/libcharon/plugins/xauth_generic` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon, cmd

## xauth_noauth
- **Rôle** : enable XAuth pseudo-backend that does not actually verify or even request any credentials.
- **Localisation** : `src/libcharon/plugins/xauth_noauth` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## xauth_pam
- **Rôle** : enable XAuth backend using PAM to verify passwords.
- **Localisation** : `src/libcharon/plugins/xauth_pam` (Bibliothèque : `libcharon`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : c, charon

## xcbc
- **Rôle** : disable xcbc crypto implementation plugin.
- **Localisation** : `src/libstrongswan/plugins/xcbc` (Bibliothèque : `libstrongswan`)
- **Plateformes supportées** : Multi-plateformes (Linux, etc.)
- **Dépendances** : Aucune (intégré)
- **Composants l'utilisant** : s, charon, nm, cmd
