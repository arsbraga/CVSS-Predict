import pandas as pd
import pickle
from pathlib import Path
from sklearn.model_selection import StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score

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

COLUNAS_R_GERAL = ['VERSAO',
                   'METRICA',
                   'FOLD',
                   'AMOSTRAS_TRAIN',
                   'AMOSTRAS_TEST',
                   'ACCURACY',
                   'PRECISION_MACRO',
                   'PRECISION_MICRO',
                   'PRECISION_WEIGHTED',
                   'RECALL_MACRO',
                   'RECALL_MICRO',
                   'RECALL_WEIGHTED',
                   'F1_MACRO',
                   'F1_MICRO',
                   'F1_WEIGHTED'
                  ]
resumo_r_geral = pd.DataFrame(columns=COLUNAS_R_GERAL)
n_splits = 5

for versao in versoes:
  for metrica in versoes[versao]['metricas']:
    print('Processando a métrica ' + metrica + ' do ' + versao)
    
    nm_col = versao + '_C_' + metrica

    if Path(f"modelos/train_indexes_{nm_col}.var").is_file() and Path(f"modelos/test_indexes_{nm_col}.var").is_file():
      print(f'Carregando índices de treinamento e teste {versao} {metrica}')
      train = pickle.load(open(f"modelos/train_indexes_{nm_col}.var",'rb'))
      test = pickle.load(open(f"modelos/test_indexes_{nm_col}.var",'rb'))
    else:
      print(f'Criando índices de treinamento e teste {versao} {metrica}')
      skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=1)
      train = []
      test = []
      for train_index, test_index in skf.split(versoes[versao]['dataset'][nm_col], versoes[versao]['dataset'][nm_col]):
        train.append(train_index)
        test.append(test_index)
      print(f'Salvando índices de treinamento e teste {versao} {metrica}')
      #pickle.dump(train, open(f"modelos/train_indexes_{nm_col}.var",'wb'))
      #pickle.dump(test, open(f"modelos/test_indexes_{nm_col}.var",'wb'))

    t_a_s = 0
    t_ps_macro = 0
    t_ps_micro = 0
    t_ps_weighted = 0
    t_r_macro = 0
    t_r_micro = 0
    t_r_weighted = 0
    t_f1_macro = 0
    t_f1_micro = 0
    t_f1_weighted = 0
    for k in range(0, len(train)):
      if Path(f"modelos/vectorizer_{nm_col}_k{k}.tfidf").is_file() and Path(f"modelos/x_{nm_col}_k{k}.tfidf").is_file(): 
        print(f"Carregando vectorizer k{k} e X k{k} do {versao} {metrica}")
        vectorizer = pickle.load(open(f"modelos/vectorizer_{nm_col}_k{k}.tfidf",'rb'))
        X = pickle.load(open(f"modelos/x_{nm_col}_k{k}.tfidf",'rb'))
      else:
        # Criar pacote de termos do modelo (treinamento)
        print(f"Criando vectorizer k{k} e X k{k} do {versao} {metrica}")
        vectorizer = TfidfVectorizer(sublinear_tf=True, min_df=2, norm='l2', ngram_range = (1,3), max_features=5000)
        X = vectorizer.fit_transform([versoes[versao]['dataset']['CVE_DESC_NLP'].to_numpy()[indice] for indice in train[k]]).toarray()
        # Salvar classifier e vectorizer
        print(f"Salvando vectorizer k{k} e X k{k} do {versao} {metrica}")
        #pickle.dump(vectorizer, open(f"modelos/vectorizer_{nm_col}_k{k}.tfidf",'wb'))
        #pickle.dump(X, open(f"modelos/x_{nm_col}_k{k}.tfidf",'wb'))

      if not Path(f"modelos/classifier_{nm_col}_{k}.model").is_file():
        print(f"Treinando modelo k = {k} do {versao} {metrica}")
        classifier = LogisticRegression(random_state=0, verbose=True).fit(X, versoes[versao]['dataset'][nm_col].to_numpy()[train[k]])
        #pickle.dump(classifier, open(f"modelos/classifier_{nm_col}_{k}.model",'wb'))
      else:
        print(f"Carregando modelo k = {k} do {versao} {metrica}")
        classifier = pickle.load(open(f"modelos/classifier_{nm_col}_{k}.model",'rb'))

      print(f"Classificando k = {k} do {versao} {metrica}")
      y_pred = classifier.predict(vectorizer.transform([versoes[versao]['dataset']['CVE_DESC_NLP'].to_numpy()[indice] for indice in test[k]]))
      y_true = versoes[versao]['dataset'][nm_col].to_numpy()[test[k]]
      # Accuracy
      a_s = accuracy_score(y_true, y_pred)
      t_a_s += a_s
      # Precision (Macro)
      ps_macro = precision_score(y_true, y_pred, average='macro')
      t_ps_macro += ps_macro
      # Precision (Micro)
      ps_micro = precision_score(y_true, y_pred, average='micro')
      t_ps_micro += ps_micro
      # Precision (Weighted)
      ps_weighted = precision_score(y_true, y_pred, average='weighted')
      t_ps_weighted += ps_weighted
      # Recall (Macro)
      r_macro = recall_score(y_true, y_pred, average='macro')
      t_r_macro += r_macro
      # Recall (Micro)
      r_micro = recall_score(y_true, y_pred, average='micro')
      t_r_micro += r_micro
      # Recall (Weighted)
      r_weighted = recall_score(y_true, y_pred, average='weighted')
      t_r_weighted += r_weighted
      # F1 (Macro)
      f1_macro = recall_score(y_true, y_pred, average='macro')
      t_f1_macro += f1_macro
      # F1 (Micro)
      f1_micro = recall_score(y_true, y_pred, average='micro')
      t_f1_micro += f1_micro
      # F1 (Weighted)
      f1_weighted = recall_score(y_true, y_pred, average='weighted')
      t_f1_weighted += f1_weighted

      #resumo_r_geral_dict = {'VERSAO': versao,
      #                       'METRICA': metrica,
      #                       'FOLD': f'F{k:02}',
      #                       'AMOSTRAS_TRAIN': len(train[k]),
      #                       'AMOSTRAS_TEST': len(test[k]),
      #                       'ACCURACY': a_s,
      #                       'PRECISION_MACRO': ps_macro,
      #                       'PRECISION_MICRO': ps_micro,
      #                       'PRECISION_WEIGHTED': ps_weighted,
      #                       'RECALL_MACRO': r_macro,
      #                       'RECALL_MICRO': r_micro,
      #                       'RECALL_WEIGHTED': r_weighted,
      #                       'F1_MACRO': f1_macro,
      #                       'F1_MICRO': f1_micro,
      #                       'F1_WEIGHTED': f1_weighted}
      #resumo_r_geral = resumo_r_geral.append(resumo_r_geral_dict, ignore_index=True)
      resumo_r_geral.loc[len(resumo_r_geral.index)] = [versao,
                                                       metrica,
                                                       f'F{k:02}',
                                                       len(train[k]),
                                                       len(test[k]),
                                                       a_s,
                                                       ps_macro,
                                                       ps_micro,
                                                       ps_weighted,
                                                       r_macro,
                                                       r_micro,
                                                       r_weighted,
                                                       f1_macro,
                                                       f1_micro,
                                                       f1_weighted]
      resumo_r_geral.to_csv(f"resultados/validacao_cruzada.csv", sep= '¨', index=False)
    #resumo_r_geral_dict = {'VERSAO': versao,
    #                       'METRICA': metrica,
    #                       'FOLD': 'MEDIA',
    #                       'AMOSTRAS_TRAIN': 0,
    #                       'AMOSTRAS_TEST': 0,
    #                       'ACCURACY': t_a_s / n_splits,
    #                       'PRECISION_MACRO': t_ps_macro / n_splits,
    #                       'PRECISION_MICRO': t_ps_micro / n_splits,
    #                       'PRECISION_WEIGHTED': t_ps_weighted / n_splits,
    #                       'RECALL_MACRO': t_r_macro / n_splits,
    #                       'RECALL_MICRO': t_r_micro / n_splits,
    #                       'RECALL_WEIGHTED': t_r_weighted / n_splits,
    #                       'F1_MACRO': t_f1_macro / n_splits,
    #                       'F1_MICRO': t_f1_micro / n_splits,
    #                       'F1_WEIGHTED': t_f1_weighted / n_splits}
    #resumo_r_geral = resumo_r_geral.append(resumo_r_geral_dict, ignore_index=True)
    resumo_r_geral.loc[len(resumo_r_geral.index)] = [versao,
                                                     metrica,
                                                     'MEDIA',
                                                     0,
                                                     0,
                                                     t_a_s / n_splits,
                                                     t_ps_macro / n_splits,
                                                     t_ps_micro / n_splits,
                                                     t_ps_weighted / n_splits,
                                                     t_r_macro / n_splits,
                                                     t_r_micro / n_splits,
                                                     t_r_weighted / n_splits,
                                                     t_f1_macro / n_splits,
                                                     t_f1_micro / n_splits,
                                                     t_f1_weighted / n_splits]
    resumo_r_geral.to_csv(f"resultados/validacao_cruzada.csv", sep= '¨', index=False)

      #print('Accuracy:', a_s)
      #print('Precision (Macro):', ps_macro)
      #print('Precision (Micro):', ps_micro)
      #print('Precision (Weighted):', ps_weighted)
      #print('Recall (Macro):', r_macro)
      #print('Recall (Micro):', r_micro)
      #print('Recall (Weighted):', r_weighted)
      #print('F1 (Macro):', f1_macro)
      #print('F1 (Micro):', f1_micro)
      #print('F1 (Weighted):', f1_weighted)
