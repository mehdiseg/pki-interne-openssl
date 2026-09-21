#!/usr/bin/env bash
# Mini-PKI interne avec OpenSSL : une autorité de certification (CA) et des certificats serveur.
#
#   ./creer-pki.sh ca [Nom de l'autorité]
#   ./creer-pki.sh serveur nom.lab [autre.nom.lab 192.168.10.5 ...]
#   ./creer-pki.sh verifier nom.lab
#
# Dossier de travail : $PKI_DIR (défaut ./pki, ignoré par git). La clé privée de la CA ne doit
# jamais quitter cette machine ; seul ca/ca.crt est distribué aux postes clients.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # évite que Git Bash transforme "/CN=..." en chemin Windows

PKI_DIR="${PKI_DIR:-./pki}"
# Sous Git Bash (Windows), openssl.exe attend des chemins Windows : on convertit si cygpath existe.
command -v cygpath >/dev/null 2>&1 && PKI_DIR="$(cygpath -m "$PKI_DIR")"
JOURS_CA=3650      # 10 ans
JOURS_SERVEUR=397  # limite acceptée par les navigateurs pour les certificats publics ; bon réflexe en interne aussi

erreur() { echo "Erreur : $*" >&2; exit 1; }
verifier_nom() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || erreur "nom invalide : « $1 »"; }

creer_ca() {
  local nom="${1:-Lab Root CA}"
  [[ "$nom" =~ ^[A-Za-z0-9\ ._-]{1,64}$ ]] || erreur "nom d'autorité invalide"
  [ -e "$PKI_DIR/ca/ca.key" ] && erreur "une autorité existe déjà dans $PKI_DIR/ca (la supprimer à la main pour recommencer)"
  mkdir -p "$PKI_DIR/ca" "$PKI_DIR/serveurs"
  ( umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$PKI_DIR/ca/ca.key" )
  openssl req -x509 -new -key "$PKI_DIR/ca/ca.key" -sha256 -days "$JOURS_CA" \
    -subj "/O=Lab BTS SIO/CN=$nom" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$PKI_DIR/ca/ca.crt"
  echo "Autorité créée : $PKI_DIR/ca/ca.crt (à installer sur les postes clients)"
}

creer_serveur() {
  local nom="$1"; shift
  verifier_nom "$nom"
  [ -e "$PKI_DIR/ca/ca.key" ] || erreur "créer d'abord l'autorité : ./creer-pki.sh ca"
  local dossier="$PKI_DIR/serveurs/$nom"
  mkdir -p "$dossier"
  local n=0 alt="" san
  for san in "$nom" "$@"; do
    n=$((n + 1))
    if [[ "$san" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      alt+="IP.$n = $san"$'\n'
    else
      verifier_nom "$san"; alt+="DNS.$n = $san"$'\n'
    fi
  done
  cat > "$dossier/extensions.cnf" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = @alt
[alt]
$alt
EXT
  ( umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dossier/$nom.key" )
  openssl req -new -key "$dossier/$nom.key" -subj "/CN=$nom" -out "$dossier/$nom.csr"
  openssl x509 -req -in "$dossier/$nom.csr" -CA "$PKI_DIR/ca/ca.crt" -CAkey "$PKI_DIR/ca/ca.key" \
    -CAcreateserial -sha256 -days "$JOURS_SERVEUR" -extfile "$dossier/extensions.cnf" \
    -out "$dossier/$nom.crt"
  # Chaîne à donner au serveur web : certificat du serveur puis celui de l'autorité
  cat "$dossier/$nom.crt" "$PKI_DIR/ca/ca.crt" > "$dossier/$nom.chaine.pem"
  echo "Certificat créé : $dossier/$nom.crt (clé : $dossier/$nom.key)"
}

verifier() {
  local nom="$1"; verifier_nom "$nom"
  local crt="$PKI_DIR/serveurs/$nom/$nom.crt"
  [ -e "$crt" ] || erreur "certificat introuvable : $crt"
  openssl verify -CAfile "$PKI_DIR/ca/ca.crt" -verify_hostname "$nom" "$crt"
  openssl x509 -in "$crt" -noout -subject -issuer -dates -ext subjectAltName
}

case "${1:-}" in
  ca)      shift; creer_ca "$@" ;;
  serveur) shift; [ $# -ge 1 ] || erreur "usage : serveur nom.lab [autres noms ou IP]"; creer_serveur "$@" ;;
  verifier) shift; [ $# -eq 1 ] || erreur "usage : verifier nom.lab"; verifier "$1" ;;
  *) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
