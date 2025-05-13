#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt

python manage.py migrate

DJANGO_SETTINGS_MODULE=proyectoSeguridad.settings python manage.py collectstatic --noinput
