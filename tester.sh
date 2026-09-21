#!/usr/bin/env bash
# Tests de bout en bout de creer-pki.sh (nécessite openssl). Code de sortie non nul au premier échec.
set -uo pipefail
export MSYS_NO_PATHCONV=1
ICI="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
command -v cygpath >/dev/null 2>&1 && TMP="$(cygpath -m "$TMP")"   # openssl.exe (Git Bash) veut des chemins Windows
PORT="${TEST_PORT:-14443}"
SERVEUR_PID=""
ECHECS=0

nettoyer() { [ -n "$SERVEUR_PID" ] && kill "$SERVEUR_PID" 2>/dev/null; rm -rf "$TMP"; }
trap nettoyer EXIT

ok()   { echo "  OK   $1"; }
ko()   { echo "  ECHEC $1"; ECHECS=$((ECHECS + 1)); }
verifie() { local nom="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$nom"; else ko "$nom"; fi; }
refuse()  { local nom="$1"; shift; if "$@" >/dev/null 2>&1; then ko "$nom (devait échouer)"; else ok "$nom"; fi; }
contient() { local nom="$1" texte="$2" motif="$3"; if grep -qE -- "$motif" <<<"$texte"; then ok "$nom"; else ko "$nom (motif absent : $motif)"; fi; }

export PKI_DIR="$TMP/pki"
PKI() { bash "$ICI/creer-pki.sh" "$@"; }

echo "== Autorité de certification"
verifie "création de la CA" PKI ca "Lab Root CA"
refuse  "une seconde CA n'écrase pas la première" PKI ca "Autre"
CA_TXT="$(openssl x509 -in "$PKI_DIR/ca/ca.crt" -noout -text)"
contient "la CA est une autorité (CA:TRUE)" "$CA_TXT" "CA:TRUE"
contient "la CA ne peut pas créer de sous-autorité (pathlen:0)" "$CA_TXT" "pathlen:0"
JOURS_CA_RESTANTS=$(( ( $(date -d "$(openssl x509 -in "$PKI_DIR/ca/ca.crt" -noout -enddate | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
if [ "$JOURS_CA_RESTANTS" -ge 3640 ] && [ "$JOURS_CA_RESTANTS" -le 3650 ]; then ok "la CA est valable environ 10 ans ($JOURS_CA_RESTANTS jours)"; else ko "durée de la CA inattendue : $JOURS_CA_RESTANTS jours"; fi

echo "== Certificat serveur"
verifie "création du certificat wiki.lab (+ alias et IP)" PKI serveur wiki.lab wiki 192.168.10.5
CRT="$PKI_DIR/serveurs/wiki.lab/wiki.lab.crt"
TXT="$(openssl x509 -in "$CRT" -noout -text)"
contient "SAN : nom principal"  "$TXT" "DNS:wiki\.lab"
contient "SAN : alias"          "$TXT" "DNS:wiki(,|$)"
contient "SAN : adresse IP"     "$TXT" "IP Address:192\.168\.10\.5"
contient "ce n'est pas une autorité (CA:FALSE)" "$TXT" "CA:FALSE"
contient "usage : serveur web (serverAuth)" "$TXT" "TLS Web Server Authentication"
contient "algorithme de signature ECDSA/SHA-256" "$TXT" "ecdsa-with-SHA256"
verifie "la chaîne est vérifiée par la CA" openssl verify -CAfile "$PKI_DIR/ca/ca.crt" "$CRT"
verifie "le nom wiki.lab correspond" openssl verify -CAfile "$PKI_DIR/ca/ca.crt" -verify_hostname wiki.lab "$CRT"
refuse  "un autre nom est refusé" openssl verify -CAfile "$PKI_DIR/ca/ca.crt" -verify_hostname intrus.lab "$CRT"
verifie "la commande « verifier » réussit" PKI verifier wiki.lab
DUREE_JOURS=$(( ( $(date -d "$(openssl x509 -in "$CRT" -noout -enddate | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
if [ "$DUREE_JOURS" -ge 390 ] && [ "$DUREE_JOURS" -le 397 ]; then ok "durée de validité d'environ 397 jours ($DUREE_JOURS)"; else ko "durée de validité inattendue : $DUREE_JOURS jours"; fi

echo "== Autre autorité"
PKI_DIR="$TMP/autre" bash "$ICI/creer-pki.sh" ca "Autorité inconnue" >/dev/null 2>&1
refuse "le certificat n'est pas accepté par une autre CA" openssl verify -CAfile "$TMP/autre/ca/ca.crt" "$CRT"

echo "== Validation des saisies"
refuse "nom avec ../ refusé"          PKI serveur "../evil"
refuse "nom avec espace refusé"       PKI serveur "a b"
refuse "nom avec point-virgule refusé" PKI serveur 'x;touch pwned'
refuse "certificat sans CA refusé"    env PKI_DIR="$TMP/vide" bash "$ICI/creer-pki.sh" serveur test.lab
[ ! -e "$TMP/pwned" ] && [ ! -e pwned ] && ok "aucune commande injectée" || ko "un fichier « pwned » a été créé"

echo "== Vraie connexion TLS (openssl s_server / s_client)"
openssl s_server -accept "$PORT" -cert "$PKI_DIR/serveurs/wiki.lab/wiki.lab.chaine.pem" -key "$PKI_DIR/serveurs/wiki.lab/wiki.lab.key" -www >/dev/null 2>&1 &
SERVEUR_PID=$!
sleep 2
client() { echo | timeout 15 openssl s_client -connect "127.0.0.1:$PORT" -CAfile "$PKI_DIR/ca/ca.crt" -verify_return_error "$@" 2>&1; }
SORTIE="$(client -verify_hostname wiki.lab)"
contient "poignée de main TLS réussie, nom wiki.lab valide" "$SORTIE" "Verify return code: 0 \(ok\)"
SORTIE="$(client -verify_ip 192.168.10.5)"
contient "l'adresse IP du SAN est valide" "$SORTIE" "Verify return code: 0 \(ok\)"
SORTIE="$(client -verify_hostname intrus.lab)"
if grep -q "Verify return code: 0 (ok)" <<<"$SORTIE"; then ko "un mauvais nom aurait dû être refusé"; else ok "un mauvais nom est refusé pendant la poignée de main"; fi
SORTIE="$(echo | timeout 15 openssl s_client -connect "127.0.0.1:$PORT" -CAfile "$TMP/autre/ca/ca.crt" -verify_return_error 2>&1)"
if grep -q "Verify return code: 0 (ok)" <<<"$SORTIE"; then ko "une CA inconnue aurait dû être refusée"; else ok "une CA inconnue est refusée pendant la poignée de main"; fi

echo
if [ "$ECHECS" -eq 0 ]; then echo "Tous les tests passent."; else echo "$ECHECS test(s) en échec."; exit 1; fi
