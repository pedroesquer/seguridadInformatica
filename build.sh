#!/usr/bin/env bash
set -o errexit

echo "Instalando dependencias..."
pip install -r requirements.txt

echo "Aplicando migraciones..."
python manage.py migrate

echo "Recolectando archivos estáticos..."
export DJANGO_SETTINGS_MODULE=proyectoSeguridad.settings
python manage.py collectstatic --noinput
