#!/bin/bash

source .venv/bin/activate
python3 -m gunicorn app:app
