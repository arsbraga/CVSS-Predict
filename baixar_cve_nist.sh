#!/bin/bash

# https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

dataset_dir="$( cd "$( dirname "$0" )" && pwd )"
dataset_dir=$dataset_dir"/dataset"

mkdir -p $dataset_dir

inicio=2002
fim=`date +'%Y'`
for ((i=inicio;i<=fim;i++)); do
    echo "Baixando arquivo NIST de $i"
    rm -f "$dataset_dir/nvdcve-1.1-$i.json.zip"
    rm -f "$dataset_dir/nvdcve-1.1-$i.json"
    wget -P $dataset_dir --no-check-certificate https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$i.json.zip
    unzip "$dataset_dir/nvdcve-1.1-$i.json.zip" -d $dataset_dir
    rm -f "$dataset_dir/nvdcve-1.1-$i.json.zip"
done

echo "Baixando arquivo NIST de $i"
rm -f "$dataset_dir/nvdcve-1.1-recent.json.zip"
rm -f "$dataset_dir/nvdcve-1.1-recent.json"
wget -P $dataset_dir --no-check-certificate https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip
unzip "$dataset_dir/nvdcve-1.1-recent.json.zip" -d $dataset_dir
rm -f "$dataset_dir/nvdcve-1.1-recent.json.zip"

chown -R divisao:divisao $dataset_dir/*

