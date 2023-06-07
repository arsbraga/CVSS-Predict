#!/bin/bash

dataset_dir="$( cd "$( dirname "$0" )" && pwd )"

mkdir -p "$dataset_dir/languages"
mkdir -p "$dataset_dir/modelos"
mkdir -p "$dataset_dir/resultados"

# https://www.argosopentech.com/argospm/index/
wget -P "$dataset_dir/languages" --no-check-certificate https://pub-dbae765fb25a4114aac1c88b90e94178.r2.dev/v1/translate-pt_en-1_0.argosmodel
mv "$dataset_dir/languages/translate-pt_en-1_0.argosmodel" "$dataset_dir/languages/pt_en.argosmodel"

./baixar_cve_nist.sh
pip install -r requirements.txt
python3 compilar_dataset.py
python3 cve_cross_validation.py
python3 cve_ia.py

