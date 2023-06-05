#!/bin/bash

./baixar_cve_nist.sh
python3 compilar_dataset.py
python3 cve_cross_validation.py
python3 cve_ia.py
