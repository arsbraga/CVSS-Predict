import os
import json
import pandas as pd
import re
import nltk

nltk.download('stopwords')
nltk.download('punkt')
nltk.download('averaged_perceptron_tagger')
nltk.download('wordnet')

from nltk.stem import WordNetLemmatizer
from nltk.corpus import wordnet
from nltk.util import ngrams
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

def c2_AVToInt(value):
  if value[0].lower() == 'n':
    return 2
  elif value[0].lower() == 'l':
    return 1
  else:
    return 0

def c2_ACToInt(value):
  if value[0].lower() == 'l':
    return 2
  elif value[0].lower() == 'm':
    return 1
  else:
    return 0

def c2_AuToInt(value):
  if value[0].lower() == 'n':
    return 2
  elif value[0].lower() == 's':
    return 1
  else:
    return 0

def c2_CToInt(value):
  if value[0].lower() == 'c':
    return 2
  elif value[0].lower() == 'p':
    return 1
  else:
    return 0

def c2_IToInt(value):
  if value[0].lower() == 'c':
    return 2
  elif value[0].lower() == 'p':
    return 1
  else:
    return 0

def c2_AToInt(value):
  if value[0].lower() == 'c':
    return 2
  elif value[0].lower() == 'p':
    return 1
  else:
    return 0

def c3_AVToInt(value):
  if value[0].lower() == 'n':
    return 3
  elif value[0].lower() == 'a':
    return 2
  elif value[0].lower() == 'l':
    return 1
  else:
    return 0

def c3_ACToInt(value):
  if value[0].lower() == 'l':
    return 1
  else:
    return 0

def c3_PRToInt(value):
  if value[0].lower() == 'h':
    return 0
  elif value[0].lower() == 'l':
    return 1
  else:
    return 2

def c3_UIToInt(value):
  if value[0].lower() == 'n':
    return 1
  else:
    return 0

def c3_SToInt(value):
  if value[0].lower() == 'c':
    return 1
  else:
    return 0

def c3_CToInt(value):
  if value[0].lower() == 'h':
    return 2
  elif value[0].lower() == 'l':
    return 1
  else:
    return 0

def c3_IToInt(value):
  if value[0].lower() == 'h':
    return 2
  elif value[0].lower() == 'l':
    return 1
  else:
    return 0

def c3_AToInt(value):
  if value[0].lower() == 'h':
    return 2
  elif value[0].lower() == 'l':
    return 1
  else:
    return 0

COLUNAS = ['CVE_ID',
           'CVE_DESC',
           'CVE_DESC_NLP',
           'CVSS2_AV',
           'CVSS2_C_AV',
           'CVSS2_AC',
           'CVSS2_C_AC',
           'CVSS2_AU',
           'CVSS2_C_AU',
           'CVSS2_C',
           'CVSS2_C_C',
           'CVSS2_I',
           'CVSS2_C_I',
           'CVSS2_A',
           'CVSS2_C_A',
           'CVSS3_AV',
           'CVSS3_C_AV',
           'CVSS3_AC',
           'CVSS3_C_AC',
           'CVSS3_PR',
           'CVSS3_C_PR',
           'CVSS3_UI',
           'CVSS3_C_UI',
           'CVSS3_S',
           'CVSS3_C_S',
           'CVSS3_C',
           'CVSS3_C_C',
           'CVSS3_I',
           'CVSS3_C_I',
           'CVSS3_A',
           'CVSS3_C_A'
          ]

cvss = pd.DataFrame(columns=COLUNAS)

pasta = "dataset"
caminhos = [os.path.join(pasta, nome) for nome in os.listdir(pasta)]
arquivos = [arq for arq in caminhos if os.path.isfile(arq)]
jsons = [arq for arq in arquivos if arq.lower().endswith(".json")]

for arq_json in jsons:
  print(f"\nProcessando Arquivo '{arq_json}'")
  with open(arq_json) as arquivo:
    data = json.load(arquivo)
    if "CVE_Items" in data:
      for cve_item in data["CVE_Items"]:
        v_ID = ""
        v_Desc = ""
        v_Desc_NLP = ""
        v2_AV = ""
        v2_C_AV = -1
        v2_AC = ""
        v2_C_AC = -1
        v2_AU = ""
        v2_C_AU = -1
        v2_C = ""
        v2_C_C = -1
        v2_I = ""
        v2_C_I = -1
        v2_A = ""
        v2_C_A = -1
        v3_AV = ""
        v3_C_AV = -1
        v3_AC = ""
        v3_C_AC = -1
        v3_PR = ""
        v3_C_PR = -1
        v3_UI = ""
        v3_C_UI = -1
        v3_S = ""
        v3_C_S = -1
        v3_C = ""
        v3_C_C = -1
        v3_I = ""
        v3_C_I = -1
        v3_A = ""
        v3_C_A = -1
        if "cve" in cve_item:
          if "CVE_data_meta" in cve_item["cve"]:
            if "ID" in cve_item["cve"]["CVE_data_meta"]:
              v_ID = cve_item["cve"]["CVE_data_meta"]["ID"]
              print("Processando", v_ID)
          if "description" in cve_item["cve"]:
            if "description_data" in cve_item["cve"]["description"]:
              for d_data in cve_item["cve"]["description"]["description_data"]:
                if "lang" in d_data:
                  if d_data["lang"] == "en":
                    if "value" in d_data:
                      v_Desc = v_Desc + " " + d_data["value"].replace("\n", " ").replace("\\n", " ").replace("\r", " ").replace("\\r", " ")
                      description = re.sub('[^a-zA-Z]',' ', v_Desc)
                      description = description.lower()
                      description = description.split() 
                      ps = PorterStemmer()
                      description = [ps.stem(word) for word in description if not word in set(stopwords.words('english'))]
                      description = ' '.join(description)
                      v_Desc_NLP = description
        if "impact" in cve_item:
          if "baseMetricV2" in cve_item["impact"]:
            if "cvssV2" in cve_item["impact"]["baseMetricV2"]:
              if "accessVector" in cve_item["impact"]["baseMetricV2"]["cvssV2"]:
                v2_AV = cve_item["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]
                v2_C_AV = c2_AVToInt(v2_AV)
              if "accessComplexity" in cve_item["impact"]["baseMetricV2"]["cvssV2"]:
                v2_AC = cve_item["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"]
                v2_C_AC = c2_ACToInt(v2_AC)
              if "authentication" in cve_item["impact"]["baseMetricV2"]["cvssV2"]:
                v2_AU = cve_item["impact"]["baseMetricV2"]["cvssV2"]["authentication"]
                v2_C_AU = c2_AuToInt(v2_AU)
              if "confidentialityImpact" in cve_item["impact"]["baseMetricV2"]["cvssV2"]:
                v2_C = cve_item["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"]
                v2_C_C = c2_CToInt(v2_C)
              if "integrityImpact" in cve_item["impact"]["baseMetricV2"]["cvssV2"]:
                v2_I = cve_item["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"]
                v2_C_I = c2_IToInt(v2_I)
              if "availabilityImpact" in cve_item["impact"]["baseMetricV2"]["cvssV2"]:
                v2_A = cve_item["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"]
                v2_C_A = c2_CToInt(v2_A)
          if "baseMetricV3" in cve_item["impact"]:
            if "cvssV3" in cve_item["impact"]["baseMetricV3"]:
              if "attackVector" in cve_item["impact"]["baseMetricV3"]["cvssV3"]:
                v3_AV = cve_item["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
                v3_C_AV = c3_AVToInt(v3_AV)
              if "attackComplexity" in cve_item["impact"]["baseMetricV3"]["cvssV3"]:
                v3_AC = cve_item["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"]
                v3_C_AC = c3_ACToInt(v3_AC)
              if "privilegesRequired" in cve_item["impact"]["baseMetricV3"]["cvssV3"]:
                v3_PR = cve_item["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"]
                v3_C_PR = c3_PRToInt(v3_PR)
              if "userInteraction" in cve_item["impact"]["baseMetricV3"]["cvssV3"]:
                v3_UI = cve_item["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"]
                v3_C_UI = c3_UIToInt(v3_UI)
              if "scope" in cve_item["impact"]["baseMetricV3"]["cvssV3"]:
                v3_S = cve_item["impact"]["baseMetricV3"]["cvssV3"]["scope"]
                v3_C_S = c3_SToInt(v3_S)
              if "confidentialityImpact" in cve_item["impact"]["baseMetricV3"]["cvssV3"]:
                v3_C = cve_item["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
                v3_C_C = c3_CToInt(v3_C)
              if "integrityImpact" in cve_item["impact"]["baseMetricV3"]["cvssV3"]:
                v3_I = cve_item["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"]
                v3_C_I = c3_IToInt(v3_I)
              if "availabilityImpact" in cve_item["impact"]["baseMetricV3"]["cvssV3"]:
                v3_A = cve_item["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"]
                v3_C_A = c3_AToInt(v3_A)
        if (len(v_ID.strip()) > 0) and (len(v_Desc.strip()) > 0) and ((len(v2_AV.strip()) > 0) or (len(v3_AV.strip()) > 0)):
          #cvss_dict = {'CVE_ID': v_ID,
          #             'CVE_DESC': v_Desc.strip(),
          #             'CVE_DESC_NLP': v_Desc_NLP.strip(),
          #             'CVSS2_AV': v2_AV,
          #             'CVSS2_C_AV': v2_C_AV,
          #             'CVSS2_AC': v2_AC,
          #             'CVSS2_C_AC': v2_C_AC,
          #             'CVSS2_AU': v2_AU,
          #             'CVSS2_C_AU': v2_C_AU,
          #             'CVSS2_C': v2_C,
          #             'CVSS2_C_C': v2_C_C,
          #             'CVSS2_I': v2_I,
          #             'CVSS2_C_I': v2_C_I,
          #             'CVSS2_A': v2_A,
          #             'CVSS2_C_A': v2_C_A,
          #             'CVSS3_AV': v3_AV,
          #             'CVSS3_C_AV': v3_C_AV,
          #             'CVSS3_AC': v3_AC,
          #             'CVSS3_C_AC': v3_C_AC,
          #             'CVSS3_PR': v3_PR,
          #             'CVSS3_C_PR': v3_C_PR,
          #             'CVSS3_UI': v3_UI,
          #             'CVSS3_C_UI': v3_C_UI,
          #             'CVSS3_S': v3_S,
          #             'CVSS3_C_S': v3_C_S,
          #             'CVSS3_C': v3_C,
          #             'CVSS3_C_C': v3_C_C,
          #             'CVSS3_I': v3_I,
          #             'CVSS3_C_I': v3_C_I,
          #             'CVSS3_A': v3_A,
          #             'CVSS3_C_A': v3_C_A}
          #cvss = cvss.append(cvss_dict, ignore_index=True)
          cvss.loc[len(cvss.index)] = [v_ID,
                                       v_Desc.strip(),
                                       v_Desc_NLP.strip(),
                                       v2_AV,
                                       v2_C_AV,
                                       v2_AC,
                                       v2_C_AC,
                                       v2_AU,
                                       v2_C_AU,
                                       v2_C,
                                       v2_C_C,
                                       v2_I,
                                       v2_C_I,
                                       v2_A,
                                       v2_C_A,
                                       v3_AV,
                                       v3_C_AV,
                                       v3_AC,
                                       v3_C_AC,
                                       v3_PR,
                                       v3_C_PR,
                                       v3_UI,
                                       v3_C_UI,
                                       v3_S,
                                       v3_C_S,
                                       v3_C,
                                       v3_C_C,
                                       v3_I,
                                       v3_C_I,
                                       v3_A,
                                       v3_C_A]
    cvss.to_csv(f"dataset/cvss.csv", sep= '¨', index=False)
