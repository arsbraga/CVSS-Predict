import pandas as pd
import joblib
from pathlib import Path
from sklearn.model_selection import StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score

storage_classifier = "modelos"

if not(Path(f"dataset/cvss_v2.csv").is_file()) or not(Path(f"dataset/cvss_v3.csv").is_file()):
  print('Carregando Banco de Dados . . .')
  ds_completo = pd.read_csv("dataset/cvss.csv", delimiter= '¨', engine = 'python')
  ds_completo.drop(['CVE_DESC', 'CVSS2_AV', 'CVSS2_AC', 'CVSS2_AU', 'CVSS2_C', 'CVSS2_I', 'CVSS2_A', 'CVSS3_AV', 'CVSS3_AC', 'CVSS3_PR', 'CVSS3_UI', 'CVSS3_S', 'CVSS3_C', 'CVSS3_I', 'CVSS3_A'], axis='columns', inplace=True)

if Path(f"dataset/cvss_v2.csv").is_file():
  print('Carregando Banco de Dados CVSS v2 . . .')
  ds_cvss_v2 = pd.read_csv("dataset/cvss_v2.csv", delimiter= '¨', engine = 'python')
else:
  print('Filtrando CVSS v2 . . .')
  ds_cvss_v2 = ds_completo[(ds_completo.CVSS2_C_AV!=-1) & (ds_completo.CVSS2_C_AC!=-1) & (ds_completo.CVSS2_C_AU!=-1) & (ds_completo.CVSS2_C_C!=-1) & (ds_completo.CVSS2_C_I!=-1) & (ds_completo.CVSS2_C_A!=-1)].copy(deep=True)
  ds_cvss_v2.drop(['CVSS3_C_AV', 'CVSS3_C_AC', 'CVSS3_C_PR', 'CVSS3_C_UI', 'CVSS3_C_S', 'CVSS3_C_C', 'CVSS3_C_I', 'CVSS3_C_A'], axis='columns', inplace=True)
  print('Salvando Banco de Dados CVSS v2 . . .')
  ds_cvss_v2.to_csv(f"dataset/cvss_v2.csv", sep= '¨', index=False)

if Path(f"dataset/cvss_v3.csv").is_file():
  print('Carregando Banco de Dados CVSS v3 . . .')
  ds_cvss_v3 = pd.read_csv("dataset/cvss_v3.csv", delimiter= '¨', engine = 'python')
else:
  print('Filtrando CVSS v3 . . .')
  ds_cvss_v3 = ds_completo[(ds_completo.CVSS3_C_AV!=-1) & (ds_completo.CVSS3_C_AC!=-1) & (ds_completo.CVSS3_C_PR!=-1) & (ds_completo.CVSS3_C_UI!=-1) & (ds_completo.CVSS3_C_S!=-1) & (ds_completo.CVSS3_C_C!=-1) & (ds_completo.CVSS3_C_I!=-1) & (ds_completo.CVSS3_C_A!=-1)].copy(deep=True)
  ds_cvss_v3.drop(['CVSS2_C_AV', 'CVSS2_C_AC', 'CVSS2_C_AU', 'CVSS2_C_C', 'CVSS2_C_I', 'CVSS2_C_A'], axis='columns', inplace=True)
  print('Salvando Banco de Dados CVSS v3 . . .')
  ds_cvss_v3.to_csv(f"dataset/cvss_v3.csv", sep= '¨', index=False)

versoes = {'CVSS2': {'metricas': ['AV', 'AC', 'AU', 'C', 'I', 'A'],
                     'dataset': ds_cvss_v2
                    },
           'CVSS3': {'metricas': ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'],
                     'dataset': ds_cvss_v3
                    }
          }

for versao in versoes:

  if Path(f"{storage_classifier}/vectorizer_{versao}.tfidf").is_file(): # and Path(f"{storage_classifier}/x_{versao}.tfidf").is_file(): 
    print(f"Carregando vectorizer e X do {versao}")
    vectorizer = joblib.load(f"{storage_classifier}/vectorizer_{versao}.tfidf")
    #X = joblib.load(f"{storage_classifier}/X_{versao}.tfidf")
  else:
    # Criar pacote de termos do modelo (treinamento)
    print(f"Criando vectorizer do {versao}")
    vectorizer = TfidfVectorizer(sublinear_tf=True, min_df=2, norm='l2', ngram_range = (1,3), max_features=5000)
    print(f"Criando X do {versao}")
    X = vectorizer.fit_transform(versoes[versao]['dataset']['CVE_DESC_NLP'].to_numpy()).toarray()
    # Salvar classifier e vectorizer
    print(f"Salvando vectorizer do {versao}")
    joblib.dump(vectorizer, f"{storage_classifier}/vectorizer_{versao}.tfidf")
    #print(f"Salvando X do {versao}")
    #joblib.dump(X, f"{storage_classifier}/X_{versao}.tfidf")

  for metrica in versoes[versao]['metricas']:
    print('Processando a métrica ' + metrica + ' do ' + versao)

    nm_col = versao + '_C_' + metrica

    if not Path(f"{storage_classifier}/classifier_{nm_col}.model").is_file():
      print(f"Treinando modelo do {versao} {metrica}")
      classifier = LogisticRegression(random_state=0, verbose=True).fit(X, versoes[versao]['dataset'][nm_col].to_numpy())
      joblib.dump(classifier, f"{storage_classifier}/classifier_{nm_col}.model")
