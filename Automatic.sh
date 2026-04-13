#!/usr/bin/env bash
# Compatibilidad con el nombre del repo; la herramienta vive en AutomaticRec.sh
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/AutomaticRec.sh" "$@"
