#!/usr/bin/env bash
# NovaShop local para GDAT en Splunk (fase 2).
#
# La imagen se construye directamente desde la copia pública de GDAT, que solo
# se lee: no se copia ni se escribe nada allí. El contenedor se publica SOLO en
# 127.0.0.1 y su stdout va a Splunk por HEC con el logging driver "splunk".
#
# Uso:
#   scripts/novashop.sh construir
#   scripts/novashop.sh arrancar [vulnerable|remediado]   (por defecto, vulnerable)
#   scripts/novashop.sh parar
#   scripts/novashop.sh estado
#
# Nota: el token HEC queda en la configuración del contenedor (docker inspect).
# Es un lab local; no publiques la salida de docker inspect.
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
# Código de NovaShop: biceps/novashop del repo gdat-azure-sentinel-lab. Por defecto se busca
# junto a este repo; se puede cambiar con NOVASHOP_SRC o en .novashop.local (no se publica).
[[ -r "$RAIZ/.novashop.local" ]] && source "$RAIZ/.novashop.local"
ORIGEN="${NOVASHOP_SRC:-$RAIZ/../gdat-azure-sentinel-lab/biceps/novashop}"
IMAGEN="gdat-novashop"
CONTENEDOR="gdat-novashop"
PUERTO="5001"

cargar_env() {
  [[ -r "$RAIZ/.env.local" ]] || { echo "Falta $RAIZ/.env.local" >&2; exit 1; }
  GDAT_HEC_TOKEN="$(grep '^GDAT_HEC_TOKEN=' "$RAIZ/.env.local" | cut -d= -f2-)"
  GDAT_HEC_URL="$(grep '^GDAT_HEC_URL=' "$RAIZ/.env.local" | cut -d= -f2-)"
  [[ -n "$GDAT_HEC_TOKEN" && -n "$GDAT_HEC_URL" ]] || { echo "Token o URL vacíos en .env.local" >&2; exit 1; }
}

construir() {
  [[ -d "$ORIGEN" ]] || { echo "No encuentro NovaShop en $ORIGEN (define NOVASHOP_SRC)" >&2; exit 1; }
  docker build -t "$IMAGEN" "$ORIGEN"
}

parar() {
  docker rm -f "$CONTENEDOR" >/dev/null 2>&1 && echo "NovaShop parada." || echo "NovaShop no estaba arrancada."
}

arrancar() {
  local modo="${1:-vulnerable}" lab
  case "$modo" in
    vulnerable) lab=true ;;
    remediado)  lab=false ;;
    *) echo "Modo desconocido: $modo (vulnerable|remediado)" >&2; exit 1 ;;
  esac
  cargar_env
  docker image inspect "$IMAGEN" >/dev/null 2>&1 || construir
  parar >/dev/null
  # Sin --restart: una app vulnerable no debe volver sola tras un reinicio.
  docker run -d --name "$CONTENEDOR" \
    -p "127.0.0.1:${PUERTO}:8000" \
    -e NOVASHOP_LAB_MODE="$lab" \
    --log-driver splunk \
    --log-opt splunk-url="$GDAT_HEC_URL" \
    --log-opt splunk-token="$GDAT_HEC_TOKEN" \
    --log-opt splunk-insecureskipverify=true \
    --log-opt splunk-index=gdat_web \
    --log-opt splunk-sourcetype=novashop:json \
    --log-opt splunk-source=novashop \
    --log-opt tag=novashop \
    "$IMAGEN" >/dev/null
  echo "NovaShop en http://127.0.0.1:${PUERTO} · modo $modo (NOVASHOP_LAB_MODE=$lab)"
}

estado() {
  docker ps -a --filter "name=^${CONTENEDOR}$" --format '{{.Names}}: {{.Status}} {{.Ports}}'
  curl -fsS -m 5 "http://127.0.0.1:${PUERTO}/health" && echo || echo "No responde en el puerto ${PUERTO}."
}

case "${1:-}" in
  construir) construir ;;
  arrancar)  arrancar "${2:-vulnerable}" ;;
  parar)     parar ;;
  estado)    estado ;;
  *) sed -n '2,15p' "$0"; exit 1 ;;
esac
