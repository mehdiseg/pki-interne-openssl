# Mini-PKI interne avec OpenSSL

[![Tests](https://github.com/mehdiseg/pki-interne-openssl/actions/workflows/tests.yml/badge.svg)](https://github.com/mehdiseg/pki-interne-openssl/actions/workflows/tests.yml)

Un script Bash pour créer sa **propre autorité de certification (CA)** et délivrer des **certificats serveur** valides pour un réseau interne : intranet, wiki, GLPI, interface d'un routeur, un service en `.lab`... Une fois la CA installée sur les postes, le navigateur affiche le cadenas sans avertissement, pour un nom qui n'existe pas sur internet (ce qui empêche d'utiliser Let's Encrypt).

Uniquement OpenSSL 3 et Bash (Linux, macOS, Git Bash sous Windows).

## Utilisation

```bash
./creer-pki.sh ca "Lab Root CA"                               # une seule fois
./creer-pki.sh serveur wiki.lab wiki 192.168.10.5             # nom principal, alias, adresse IP
./creer-pki.sh verifier wiki.lab
```

Résultat de la dernière commande :

```text
pki/serveurs/wiki.lab/wiki.lab.crt: OK
subject=CN=wiki.lab
issuer=O=Lab BTS SIO, CN=Lab Root CA
notBefore=Sep 21 17:26:07 2026 GMT
notAfter=Oct 23 17:26:07 2027 GMT
X509v3 Subject Alternative Name:
    DNS:wiki.lab, DNS:wiki, IP Address:192.168.10.5
```

Arborescence créée dans `pki/` (variable `PKI_DIR` pour changer d'emplacement, dossier ignoré par git) :

```text
pki/ca/ca.key, ca.crt                        clé privée et certificat de l'autorité
pki/serveurs/wiki.lab/wiki.lab.key           clé privée du serveur
pki/serveurs/wiki.lab/wiki.lab.crt           certificat du serveur (signé par la CA)
pki/serveurs/wiki.lab/wiki.lab.chaine.pem    certificat du serveur + celui de la CA (à donner au serveur web)
```

## Ce que produit le script, et pourquoi

| Choix | Raison |
|---|---|
| Clés **ECDSA P-256**, signature SHA-256 | courtes, rapides, acceptées partout |
| CA `CA:TRUE, pathlen:0`, usage `keyCertSign, cRLSign` | elle ne peut signer que des certificats finaux, pas d'autres autorités |
| Certificat serveur `CA:FALSE`, usage `serverAuth` | il ne peut pas servir à signer d'autres certificats |
| Extension **subjectAltName** obligatoire | les navigateurs ignorent le `CN` : seul le SAN compte |
| Validité 397 jours (serveur), 10 ans (CA) | des certificats courts limitent les dégâts d'une fuite |
| Clés privées créées avec `umask 077` | lisibles par leur seul propriétaire |
| Noms validés par expression régulière | pas d'injection de commande ni de chemin (`../`) |
| Refus d'écraser une CA existante | une seconde exécution ne doit pas invalider tous les certificats émis |

## Utiliser le certificat

**nginx** :

```nginx
server {
    listen 443 ssl;
    server_name wiki.lab;
    ssl_certificate     /etc/nginx/tls/wiki.lab.chaine.pem;
    ssl_certificate_key /etc/nginx/tls/wiki.lab.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
}
```

**Faire confiance à la CA sur les postes** (distribuer uniquement `ca.crt`, **jamais** `ca.key`) :

- Windows (terminal administrateur) : `certutil -addstore -f "ROOT" ca.crt`. En entreprise, la diffusion se fait par GPO (*Configuration ordinateur → Paramètres Windows → Paramètres de sécurité → Stratégies de clé publique → Autorités de certification racines de confiance*).
- Debian / Ubuntu : copier le fichier dans `/usr/local/share/ca-certificates/lab-root-ca.crt` puis `sudo update-ca-certificates`.
- Firefox utilise son propre magasin : *Paramètres → Vie privée et sécurité → Certificats → Afficher les certificats → Autorités → Importer*.

## Tests

```bash
bash tester.sh
```

27 vérifications, dont une **vraie connexion TLS** : le script lance `openssl s_server` avec le certificat créé, puis `openssl s_client` valide la chaîne et le nom. Il contrôle aussi que :

- la CA est bien une autorité limitée (`CA:TRUE`, `pathlen:0`) et le certificat serveur ne l'est pas ;
- le SAN contient le nom, l'alias et l'adresse IP demandés ;
- un **autre nom** (`intrus.lab`) est refusé, comme un certificat vérifié avec une **autre CA** ;
- les noms piégés (`../evil`, `a b`, `x;touch pwned`) sont rejetés sans exécuter de commande ;
- une seconde création de CA n'écrase pas la première.

Les tests s'exécutent aussi à chaque `push` (GitHub Actions, Ubuntu).

## Limites

- **Pas de révocation** (ni CRL ni OCSP) : si une clé fuit, il faut retirer la confiance à la CA ou attendre l'expiration. Pour un vrai parc, regarder [smallstep `step-ca`](https://smallstep.com/docs/step-ca/) ou l'AD CS de Windows Server.
- La clé de la CA n'est pas chiffrée par mot de passe : à ranger sur un poste protégé et sauvegardé hors ligne.
- Pas de renouvellement automatique : penser à réémettre les certificats avant les 397 jours (la commande `serveur` sert aussi à cela).
- Un TP d'apprentissage, pas une PKI de production.

