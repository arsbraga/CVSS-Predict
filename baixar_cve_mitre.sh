#!/bin/bash

# https://www.cve.org/Downloads

dataset_dir="$( cd "$( dirname "$0" )" && pwd )"
dataset_dir=$dataset_dir"/dataset"

mkdir -p $dataset_dir

wget -P $dataset_dir --no-check-certificate https://cve.mitre.org/data/downloads/allitems.csv.Z
uncompress $dataset_dir"/allitems.csv.Z"
chown -R divisao:divisao $dataset_dir/*

