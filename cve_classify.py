import sys
import numpy as np
import pandas as pd
import joblib
import nltk
import re
import pprint
import math
from argostranslate import package, translate
from nltk.stem import WordNetLemmatizer
from nltk.corpus import wordnet
from nltk.util import ngrams
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from pathlib import Path
from sklearn.model_selection import StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score

storage_classifier = "modelos"

# Download and install NLTK packages
def DownloadNLTKParts():
  nltk.download('stopwords')
  nltk.download('punkt')
  nltk.download('averaged_perceptron_tagger')
  nltk.download('wordnet')

# Funções de codificação de métricas
def CVSS2AVIntToFloat(value):
  if value == 2:
    return 1.0 # Network accessible
  elif value == 1:
    return 0.646 # Local Network accessible
  else:
    return 0.395 # Requires local access

def CVSS2ACIntToFloat(value):
  if value == 2:
    return 0.71 # Low
  elif value == 1:
    return 0.61 # Medium
  else:
    return 0.35 # High

def CVSS2AuIntToFloat(value):
  if value == 2:
    return 0.704 # Requires no authentication
  elif value == 1:
    return 0.56 # Requires single instance of authentication
  else:
    return 0.45 # Requires multiple instances of authentication

def CVSS2CIntToFloat(value):
  if value == 2:
    return 0.660 # complete
  elif value == 1:
    return 0.275 # partial
  else:
    return 0 # none

def CVSS2IIntToFloat(value):
  if value == 2:
    return 0.660 # complete
  elif value == 1:
    return 0.275 # partial
  else:
    return 0 # none

def CVSS2AIntToFloat(value):
  if value == 2:
    return 0.660 # complete
  elif value == 1:
    return 0.275 # partial
  else:
    return 0 # none

def CVSS3AVIntToFloat(value):
  if value == 3:
    return 0.85 # Network Accessible
  elif value == 2:
    return 0.62 # Adjacent Network Accessible
  elif value == 1:
    return 0.55 # Local Access
  else:
    return 0.2 # Physical Interaction

def CVSS3ACIntToFloat(value):
  if value == 1:
    return 0.77 # Low
  else:
    return 0.44 # High

def CVSS3PRIntToFloat(value, S):
  if value == 0:
    if S == 0:
      return 0.27 # High Unchanged
    else:
      return 0.5 # High Changed
  elif value == 1:
    if S == 0:
      return 0.62 # Low Unchanged
    else:
      return 0.68 # Low Changed
  else:
    return 0.85 # None

def CVSS3UIIntToFloat(value):
  if value == 1:
    return 0.85 # None
  else:
    return 0.62 # Required

def CVSS3CIntToFloat(value):
  if value == 2:
    return 0.56 # High
  elif value == 1:
    return 0.22 # Low
  else:
    return 0 # None

def CVSS3IIntToFloat(value):
  if value == 2:
    return 0.56 # High
  elif value == 1:
    return 0.22 # Low
  else:
    return 0 # None

def CVSS3AIntToFloat(value):
  if value == 2:
    return 0.56 # High
  elif value == 1:
    return 0.22 # Low
  else:
    return 0 # None

# Pontuação
def CVSS2ImpactValue(C, I, A):
  return 10.41 * (1 - (1 - C) * (1 - I) * (1 - A))

def CVSS2fImpactValue(C, I, A):
  return 0 if CVSS2ImpactValue(C, I, A) == 0 else 1.176

def CVSS2ExploitabilityValue(AV, AC, AU):
  return 20 * AV * AC * AU

def CVSS2BaseScoreValue(AV, AC, AU, C, I, A):
  IV = CVSS2ImpactValue(C, I, A)
  EV = CVSS2ExploitabilityValue(AV, AC, AU)
  fIV = CVSS2fImpactValue(C, I, A)
  retorno = abs(round(((0.6 * IV) + (0.4 * EV - 1.5)) * fIV, 1))
  return retorno

def CVSS2Severity(BaseScore):
  if BaseScore < 4:
    return "LOW"
  elif BaseScore < 7:
    return "MEDIUM"
  else:
    return "HIGH"

def Roundup(input):
  int_input = round(input * 100000)
  if (int_input % 10000) == 0:
    return int_input / 100000.0
  else:
    return (math.floor(int_input / 10000) + 1) / 10.0

def CVSS3ImpactValue(S, C, I, A):
  iss = 1 - ((1 - C) * (1 - I) * (1 - A))
  if S == 0: # Unchanged
    return 6.42 * iss
  else: # Changed
    return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)**15

def CVSS3ExploitabilityValue(AV, AC, PR, UI):
  return 8.22 * AV * AC * PR * UI

def CVSS3BaseScoreValue(AV, AC, PR, UI, S, C, I, A):
  IV = CVSS3ImpactValue(S, C, I, A)
  EV = CVSS3ExploitabilityValue(AV, AC, PR, UI)
  if IV <= 0:
    return 0
  else:
    if S == 0: # Unchanged
      return Roundup(min((IV + EV), 10))
    else: # Changed
      return Roundup(min(1.08 * (IV + EV), 10))

def CVSS3Severity(BaseScore):
  if BaseScore == 0:
    return "NONE"
  elif BaseScore < 4:
    return "LOW"
  elif BaseScore < 7:
    return "MEDIUM"
  elif BaseScore < 9:
    return "HIGH"
  else:
    return "CRITICAL"

# Funções de nomes das classes de métricas
def CVSS2AVIntToStr(value):
  if value == 2:
    return 'Network Accessible'
  elif value == 1:
    return 'Local Network Accessible'
  else:
    return 'Requires Local Access'

def CVSS2ACIntToStr(value):
  if value == 2:
    return 'Low'
  elif value == 1:
    return 'Medium'
  else:
    return 'High'

def CVSS2AuIntToStr(value):
  if value == 2:
    return 'Requires no Authentication'
  elif value == 1:
    return 'Requires Single Instance of Authentication'
  else:
    return 'Requires Multiple Instances of Authentication'

def CVSS2CIntToStr(value):
  if value == 2:
    return 'Complete'
  elif value == 1:
    return 'Partial'
  else:
    return 'None'

def CVSS2IIntToStr(value):
  if value == 2:
    return 'Complete'
  elif value == 1:
    return 'Partial'
  else:
    return 'None'

def CVSS2AIntToStr(value):
  if value == 2:
    return 'Complete'
  elif value == 1:
    return 'Partial'
  else:
    return 'None'

def CVSS2IntToStr(metrica, value):
  if metrica == 'AV':
    return CVSS2AVIntToStr(value)
  elif metrica == 'AC':
    return CVSS2ACIntToStr(value)
  elif metrica == 'AU':
    return CVSS2AuIntToStr(value)
  elif metrica == 'C':
    return CVSS2CIntToStr(value)
  elif metrica == 'I':
    return CVSS2IIntToStr(value)
  elif metrica == 'A':
    return CVSS2AIntToStr(value)
  else:
    return ''

def CVSS3AVIntToStr(value):
  if value == 3:
    return 'Network Accessible'
  elif value == 2:
    return 'Adjacent Network Accessible'
  elif value == 1:
    return 'Local Access'
  else:
    return 'Physical Interaction'

def CVSS3ACIntToStr(value):
  if value == 1:
    return 'Low'
  else:
    return 'High'

def CVSS3PRIntToStr(value):
  if value == 0:
    return 'High'
  elif value == 1:
    return 'Low'
  else:
    return 'None'

def CVSS3UIIntToStr(value):
  if value == 1:
    return 'None'
  else:
    return 'Required'

def CVSS3SIntToStr(value):
  if value == 1:
    return 'Changed'
  else:
    return 'Unchanged'

def CVSS3CIntToStr(value):
  if value == 2:
    return 'High'
  elif value == 1:
    return 'Low'
  else:
    return 'None'

def CVSS3IIntToStr(value):
  if value == 2:
    return 'High'
  elif value == 1:
    return 'Low'
  else:
    return 'None'

def CVSS3AIntToStr(value):
  if value == 2:
    return 'High'
  elif value == 1:
    return 'Low'
  else:
    return 'None'

def CVSS3IntToStr(metrica, value):
  if metrica == 'AV':
    return CVSS3AVIntToStr(value)
  elif metrica == 'AC':
    return CVSS3ACIntToStr(value)
  elif metrica == 'PR':
    return CVSS3PRIntToStr(value)
  elif metrica == 'UI':
    return CVSS3UIIntToStr(value)
  elif metrica == 'S':
    return CVSS3SIntToStr(value)
  elif metrica == 'C':
    return CVSS3CIntToStr(value)
  elif metrica == 'I':
    return CVSS3IIntToStr(value)
  elif metrica == 'A':
    return CVSS3AIntToStr(value)
  else:
    return ''

# Funções de Textos referentes às métricas mais bem pontuadas

def CVSS2AVIntToText(value):
  if value == 2:
    return 'Uma vulnerabilidade explorável com acesso à rede significa que o software vulnerável está vinculado à pilha de rede e o invasor não precisa ter acesso à rede local. Essa vulnerabilidade é frequentemente chamada de "explorável remotamente".'
  elif value == 1:
    return 'Uma vulnerabilidade explorável com acesso à rede local exige que o invasor tenha acesso ao domínio de transmissão ou colisão do software vulnerável. Exemplos de redes locais incluem sub-rede IP local, Bluetooth, IEEE 802.11 e segmento Ethernet local.'
  else:
    return 'Uma vulnerabilidade explorável apenas com acesso local exige que o invasor tenha acesso físico ao sistema vulnerável ou uma conta local (shell). Exemplos de vulnerabilidades exploráveis localmente são ataques periféricos, como ataques Firewire/USB DMA e escalações de privilégios locais (por exemplo, sudo).'

def CVSS2ACIntToText(value):
  if value == 2:
    return 'Quanto à complexidade de acesso, não há condições de acesso especializado ou circunstâncias atenuantes.'
  elif value == 1:
    return 'As condições de acesso são especializadas, como por exemplo: a parte atacante está limitada a um grupo de sistemas ou usuários em algum nível de autorização, possivelmente não confiável; algumas informações devem ser coletadas antes que um ataque bem-sucedido possa ser lançado; a configuração afetada não é padrão e não é comumente; ou o ataque requer uma pequena quantidade de engenharia social que pode, ocasionalmente, enganar usuários cautelosos.'
  else:
    return 'Há condições de acesso especializadas, como por exemplo: o atacante já deve ter privilégios elevados; ou o ataque depende de métodos de engenharia social que seriam facilmente detectados por pessoas experientes.'

def CVSS2AuIntToText(value):
  if value == 2:
    return 'A autenticação não é necessária para explorar a vulnerabilidade.'
  elif value == 1:
    return 'A vulnerabilidade requer que um invasor esteja conectado ao sistema (como em uma linha de comando ou por meio de uma sessão de desktop ou interface da web).'
  else:
    return 'A exploração da vulnerabilidade requer que o invasor autentique duas ou mais vezes, inclusive se as mesmas credenciais forem usadas todas as vezes. Um exemplo é a autenticação de um invasor em um sistema operacional, além de fornecer credenciais para acessar um aplicativo hospedado nesse sistema.'

def CVSS2CIntToText(value):
  if value == 2:
    return 'Há total divulgação de informações, resultando na revelação de todos os arquivos do sistema. O invasor consegue ler todos os dados do sistema (memória, arquivos, etc.). '
  elif value == 1:
    return 'Há considerável impacto na confidencialidade em virtude da divulgação de informações. O acesso a alguns arquivos do sistema é possível, mas o invasor não tem controle sobre o que é obtido ou o escopo da perda é limitado.'
  else:
    return 'Não há impacto na confidencialidade do sistema.'

def CVSS2IIntToText(value):
  if value == 2:
    return 'Há um comprometimento total da integridade do sistema. Há uma perda completa da proteção do sistema, resultando no comprometimento de todo o sistema. O invasor é capaz de modificar quaisquer informações no sistema de destino.'
  elif value == 1:
    return 'A modificação de alguns arquivos ou informações do sistema é possível, mas o invasor não tem controle sobre o que pode ser modificado ou o escopo do que o invasor pode afetar é limitado.'
  else:
    return 'Não há impacto na integridade do sistema.'

def CVSS2AIntToText(value):
  if value == 2:
    return 'Pode haver indisponibilidade total do recurso afetado.'
  elif value == 1:
    return 'Há desempenho reduzido ou interrupções na disponibilidade de recursos. Um exemplo é um ataque de inundação baseado em rede que permite um número limitado de conexões bem-sucedidas a um serviço de Internet.'
  else:
    return 'Não há impacto na disponibilidade do sistema.'

def CVSS3AVIntToText(value):
  if value == 3:
    return 'No que conerne ao vetor de ataque, o componente vulnerável está vinculado à pilha de rede e o conjunto de possíveis invasores se estende até a Internet. Essa vulnerabilidade costuma ser chamada de “explorável remotamente” e pode ser considerada um ataque explorável, a nível de protocolo, a um ou mais saltos de rede (por exemplo, em um ou mais roteadores).'
  elif value == 2:
    return 'No que conerne ao vetor de ataque, o componente vulnerável está vinculado à pilha de rede, mas o ataque é limitado, a nível de protocolo, a uma topologia logicamente adjacente. Isso pode significar que um ataque deve ser iniciado a partir da mesma rede física compartilhada (por exemplo, Bluetooth ou IEEE 802.11) ou lógica (por exemplo, sub-rede IP local) ou de um domínio administrativo seguro ou limitado (por exemplo, MPLS ou VPN). Um exemplo de ataque adjacente seria uma inundação ARP (IPv4) ou descoberta de vizinho (IPv6) levando a uma negação de serviço no segmento LAN local.'
  elif value == 1:
    return 'No que conerne ao vetor de ataque, o componente vulnerável não está vinculado à pilha de rede e o caminho do invasor é por meio de recursos de leitura/gravação/execução. Assim, ou invasor explora a vulnerabilidade acessando o sistema de destino localmente (por exemplo, teclado ou console) ou remotamente (por exemplo, SSH); ou o invasor depende da interação de um usuário que execute as ações necessárias para explorar a vulnerabilidade (por exemplo, usar técnicas de engenharia social para induzir um usuário legítimo a abrir um documento malicioso).'
  else:
    return 'No que conerne ao vetor de ataque, é exigido que o invasor toque ou manipule fisicamente o componente vulnerável. A interação física pode ser breve ou persistente. Um exemplo desse tipo de ataque é um ataque de inicialização a frio no qual um invasor obtém acesso às chaves de criptografia de disco após acessar fisicamente o sistema de destino. Outros exemplos incluem ataques periféricos via FireWire/USB Direct Memory Access (DMA).'

def CVSS3ACIntToText(value):
  if value == 1:
    return 'No prisma da complexidade do ataque, não há condições de acesso especializadas ou circunstâncias atenuantes. Um invasor pode esperar um sucesso repetível ao atacar o componente vulnerável.'
  else:
    return 'No prisma da complexidade do ataque, para que este seja bem-sucedido, há a dependência de condições além do controle do atacante. Ou seja, um ataque bem-sucedido não pode ser realizado à vontade, mas exige que o invasor invista em uma quantidade mensurável de esforço na preparação ou execução contra o componente vulnerável antes que um ataque bem-sucedido possa ser esperado. Por exemplo, um ataque bem-sucedido pode depender de um invasor superando qualquer uma das seguintes condições: conhecimento sobre o ambiente no qual o alvo/componente vulnerável existe; o invasor deve preparar o ambiente de destino para melhorar a confiabilidade da exploração; ou o invasor deve estar no caminho lógico da rede entre o alvo e o recurso solicitado pela vítima para ler e/ou modificar as comunicações de rede.'

def CVSS3PRIntToText(value):
  if value == 0:
    return 'Os privilégios requeridos são de controle significativo sobre o componente vulnerável (por exemplo, administrativo), permitindo acesso a configurações e arquivos de todo o componente.'
  elif value == 1:
    return 'Os privilégios requeridos são os recursos básicos de usuário, que normalmente podem afetar apenas configurações e arquivos pertencentes a um usuário. Normalmente, o acesso é limitado a recursos não confidenciais.'
  else:
    return 'Não há privilégio requerido. Assim, o invasor não é autorizado antes do ataque e, portanto, não requer nenhum acesso às configurações ou arquivos do sistema vulnerável para realizar um ataque.'

def CVSS3UIIntToText(value):
  if value == 1:
    return 'O sistema vulnerável pode ser explorado sem interação de qualquer usuário.'
  else:
    return 'A exploração bem-sucedida desta vulnerabilidade exige que o usuário execute alguma ação antes que a vulnerabilidade possa ser explorada.'

def CVSS3SIntToText(value):
  if value == 1:
    return 'Como o escopo é alterado, a vulnerabilidade explorada pode afetar recursos além do escopo de segurança gerenciado pela autoridade de segurança do componente vulnerável.'
  else:
    return 'O escopo é inalterado, ou seja, uma vulnerabilidade explorada só pode afetar os recursos gerenciados pela mesma autoridade de segurança. Nesse caso, o componente vulnerável e o componente afetado são os mesmos ou ambos são gerenciados pela mesma autoridade de segurança.'

def CVSS3CIntToText(value):
  if value == 2:
    return 'Há uma perda total de confidencialidade, resultando na divulgação de todos os recursos do componente afetado ao invasor.'
  elif value == 1:
    return 'Há alguma perda de confidencialidade. O acesso a algumas informações restritas é obtido, mas o invasor não tem controle sobre quais informações são obtidas ou a quantidade ou tipo de perda é limitada. A divulgação de informações pode não causa prejuízo direto e sério ao componente impactado.'
  else:
    return 'Não há perda de confidencialidade no componente afetado.'

def CVSS3IIntToText(value):
  if value == 2:
    return 'Há uma perda total de integridade ou uma perda completa de proteção. Por exemplo, o invasor pode modificar qualquer/todos os arquivos protegidos pelo componente afetado. A modificação maliciosa poderia apresentar uma consequência direta e séria ao componente afetado.'
  elif value == 1:
    return 'O impacto na integridade é baixa em virtude do invasor não ter controle sobre as consequências de uma modificação ou a quantidade de modificação é limitada, embora haja a possibilidade da modificação de dados. A modificação de dados não tem um impacto sério e direto no componente afetado.'
  else:
    return 'Não há perda de integridade no componente afetado.'

def CVSS3AIntToText(value):
  if value == 2:
    return 'Há uma perda total de disponibilidade, fazendo com que o invasor seja capaz de negar totalmente o acesso aos recursos no componente afetado; essa perda é sustentada (enquanto o atacante continua a desferir o ataque) ou persistente (a condição persiste mesmo após a conclusão do ataque). A perda de disponibilidade pode apresentar uma consequência direta e séria para o componente afetado.'
  elif value == 1:
    return 'O desempenho é reduzido ou há interrupções na disponibilidade de recursos. Mesmo que a exploração repetida da vulnerabilidade seja possível, o invasor não tem a capacidade de negar completamente o serviço a usuários legítimos. Os recursos no componente afetado estão parcialmente disponíveis o tempo todo ou totalmente disponíveis apenas em parte do tempo, mas, em geral, não há nenhuma consequência direta e séria para o componente afetado.'
  else:
    return 'Não há impacto na disponibilidade do componente afetado.'

def contar_espacos(value):
  contador = 0
  for caractere in value.strip():
    if caractere == " ":
      contador += 1
  return contador

def LoadVectorizers():
  if Path(f"{storage_classifier}/vectorizer_CVSS2.tfidf").is_file(): 
    print(f"Carregando vectorizer do CVSS2")
    vectorizer2 = joblib.load(f"{storage_classifier}/vectorizer_CVSS2.tfidf")
  else:
    sys.exit("Vectorizer do CVSS2 não encontrado.")

  if Path(f"{storage_classifier}/vectorizer_CVSS3.tfidf").is_file(): 
    print(f"Carregando vectorizer do CVSS3")
    vectorizer3 = joblib.load(f"{storage_classifier}/vectorizer_CVSS3.tfidf")
  else:
    sys.exit("Vectorizer do CVSS3 não encontrado.")

  return vectorizer2, vectorizer3

def LoadModels():
  versoes = {'CVSS2': {'metricas': ['AV', 'AC', 'AU', 'C', 'I', 'A'],
                       'classifier': [None, None, None, None, None, None]
                      },
             'CVSS3': {'metricas': ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'],
                       'classifier': [None, None, None, None, None, None, None, None]
                      }
            }

  for versao in versoes:
    for i, metrica in enumerate(versoes[versao]['metricas']):
      nm_col = versao + '_C_' + metrica

      if Path(f"{storage_classifier}/classifier_{nm_col}.model").is_file(): 
        print(f'Carregando classificador da métrica {metrica} do {versao}')
        versoes[versao]['classifier'][i] = joblib.load(f"{storage_classifier}/classifier_{nm_col}.model")
      else:
        sys.exit(f"Classificador da métrica {metrica} do {versao} não encontrado.")

  return versoes

def DealTextNLP(text):
  description = re.sub('[^a-zA-Z]',' ',text)
  description = description.lower()
  description = description.split()
  ps = PorterStemmer()
  description = [ps.stem(word) for word in description if not word in set(stopwords.words('english'))]
  description = ' '.join(description)
  return description

def VectorizerText(text, vectorizer):
  vuln_terms = []
  temp_vectorizer = TfidfVectorizer(sublinear_tf=True, norm='l2', ngram_range = (1,3), max_features=5000)
  temp_vectorizer.fit_transform(np.array([text])).toarray()
  VectorizedText = vectorizer.transform([text])
  terms = vectorizer.inverse_transform(VectorizedText)
  for term in temp_vectorizer.get_feature_names_out():
    vuln_terms.append({'term': term, 'vectorized': term in vectorizer.get_feature_names_out()})
  return VectorizedText.toarray()[0], vuln_terms

def Predict(text, vectorizer2, vectorizer3, models):
  txt = DealTextNLP(text)
  ret = {}
  txt_vectorized2, vuln_terms2 = VectorizerText(txt, vectorizer2)
  txt_vectorized3, vuln_terms3 = VectorizerText(txt, vectorizer3)
  for model in models:
    ret[model] = {}
    ret[model]['metricas'] = {}
    for i, metrica in enumerate(models[model]['metricas']):
      if model == 'CVSS2':
        y = models[model]['classifier'][i].predict_proba([txt_vectorized2])
      else:
        y = models[model]['classifier'][i].predict_proba([txt_vectorized3])
      ret[model]['metricas'][metrica] = {}
      ret[model]['metricas'][metrica]['code_classes'] = models[model]['classifier'][i].classes_
      ret[model]['metricas'][metrica]['name_classes'] = []
      if model == 'CVSS2':
        for code in ret[model]['metricas'][metrica]['code_classes']:
          ret[model]['metricas'][metrica]['name_classes'].append(CVSS2IntToStr(metrica, code))
      else:
        for code in ret[model]['metricas'][metrica]['code_classes']:
          ret[model]['metricas'][metrica]['name_classes'].append(CVSS3IntToStr(metrica, code))
      ret[model]['metricas'][metrica]['predict_proba'] = y[0]
      ret[model]['metricas'][metrica]['index_proba'] = np.where(y[0] == np.max(y[0]))[0][0]
    if model == 'CVSS2':
      ret[model]['BaseScore'] = CVSS2BaseScoreValue(CVSS2AVIntToFloat(ret[model]['metricas']['AV']['code_classes'][ret[model]['metricas']['AV']['index_proba']]),
                                                    CVSS2ACIntToFloat(ret[model]['metricas']['AC']['code_classes'][ret[model]['metricas']['AC']['index_proba']]),
                                                    CVSS2AuIntToFloat(ret[model]['metricas']['AU']['code_classes'][ret[model]['metricas']['AU']['index_proba']]),
                                                    CVSS2CIntToFloat(ret[model]['metricas']['C']['code_classes'][ret[model]['metricas']['C']['index_proba']]),
                                                    CVSS2IIntToFloat(ret[model]['metricas']['I']['code_classes'][ret[model]['metricas']['I']['index_proba']]),
                                                    CVSS2AIntToFloat(ret[model]['metricas']['A']['code_classes'][ret[model]['metricas']['A']['index_proba']]))
      ret[model]['Severity'] = CVSS2Severity(ret[model]['BaseScore'])
      ret[model]['TextualResponse'] = CVSS2AVIntToText(ret[model]['metricas']['AV']['code_classes'][ret[model]['metricas']['AV']['index_proba']]) + ' ' + CVSS2ACIntToText(ret[model]['metricas']['AC']['code_classes'][ret[model]['metricas']['AC']['index_proba']]) + ' ' + CVSS2AuIntToText(ret[model]['metricas']['AU']['code_classes'][ret[model]['metricas']['AU']['index_proba']]) + ' ' + CVSS2CIntToText(ret[model]['metricas']['C']['code_classes'][ret[model]['metricas']['C']['index_proba']]) + ' ' + CVSS2IIntToText(ret[model]['metricas']['I']['code_classes'][ret[model]['metricas']['I']['index_proba']]) + ' ' + CVSS2AIntToText(ret[model]['metricas']['A']['code_classes'][ret[model]['metricas']['A']['index_proba']])
    else:
      ret[model]['BaseScore'] = CVSS3BaseScoreValue(CVSS3AVIntToFloat(ret[model]['metricas']['AV']['code_classes'][ret[model]['metricas']['AV']['index_proba']]),
                                                    CVSS3ACIntToFloat(ret[model]['metricas']['AC']['code_classes'][ret[model]['metricas']['AC']['index_proba']]),
                                                    CVSS3PRIntToFloat(ret[model]['metricas']['PR']['code_classes'][ret[model]['metricas']['PR']['index_proba']],
                                                                      ret[model]['metricas']['S']['code_classes'][ret[model]['metricas']['S']['index_proba']]),
                                                    CVSS3UIIntToFloat(ret[model]['metricas']['UI']['code_classes'][ret[model]['metricas']['UI']['index_proba']]),
                                                    ret[model]['metricas']['S']['code_classes'][ret[model]['metricas']['S']['index_proba']],
                                                    CVSS3CIntToFloat(ret[model]['metricas']['C']['code_classes'][ret[model]['metricas']['C']['index_proba']]),
                                                    CVSS3IIntToFloat(ret[model]['metricas']['I']['code_classes'][ret[model]['metricas']['I']['index_proba']]),
                                                    CVSS3AIntToFloat(ret[model]['metricas']['A']['code_classes'][ret[model]['metricas']['A']['index_proba']]))
      ret[model]['Severity'] = CVSS3Severity(ret[model]['BaseScore'])
      ret[model]['TextualResponse'] = CVSS3AVIntToText(ret[model]['metricas']['AV']['code_classes'][ret[model]['metricas']['AV']['index_proba']]) + ' ' + CVSS3ACIntToText(ret[model]['metricas']['AC']['code_classes'][ret[model]['metricas']['AC']['index_proba']]) + ' ' + CVSS3PRIntToText(ret[model]['metricas']['PR']['code_classes'][ret[model]['metricas']['PR']['index_proba']]) + ' ' + CVSS3UIIntToText(ret[model]['metricas']['UI']['code_classes'][ret[model]['metricas']['UI']['index_proba']]) + ' ' + CVSS3SIntToText(ret[model]['metricas']['S']['code_classes'][ret[model]['metricas']['S']['index_proba']]) + ' ' + CVSS3CIntToText(ret[model]['metricas']['C']['code_classes'][ret[model]['metricas']['C']['index_proba']]) + ' ' + CVSS3IIntToText(ret[model]['metricas']['I']['code_classes'][ret[model]['metricas']['I']['index_proba']]) + ' ' + CVSS3AIntToText(ret[model]['metricas']['A']['code_classes'][ret[model]['metricas']['A']['index_proba']])
  ret['CVSS2']['Terms'] = vuln_terms2
  proc_term = 0
  proc_unigram = 0
  proc_bigram = 0
  proc_trigram = 0
  unigram = 0
  bigram = 0
  trigram = 0
  for term in vuln_terms2:
    zeros = contar_espacos(term['term'])
    if term['vectorized']:
      proc_term += 1
      if zeros == 0:
        proc_unigram += 1
      elif zeros == 1:
        proc_bigram += 1
      elif zeros == 2:
        proc_trigram += 1
    if zeros == 0:
      unigram += 1
    elif zeros == 1:
      bigram += 1
    elif zeros == 2:
      trigram += 1
  ret['CVSS2']['Statistics'] = {}
  ret['CVSS2']['Statistics']['Terms_Total'] = len(vuln_terms2)
  ret['CVSS2']['Statistics']['Terms_Processed'] = proc_term
  ret['CVSS2']['Statistics']['Terms_Perc_Processed'] = proc_term / len(vuln_terms2)

  ret['CVSS2']['Statistics']['Unigram_Total'] = unigram
  ret['CVSS2']['Statistics']['Unigram_Processed'] = proc_unigram
  ret['CVSS2']['Statistics']['Unigram_Perc_Processed'] = proc_unigram / unigram

  ret['CVSS2']['Statistics']['Bigram_Total'] = bigram
  ret['CVSS2']['Statistics']['Bigram_Processed'] = proc_bigram
  ret['CVSS2']['Statistics']['Bigram_Perc_Processed'] = proc_bigram / bigram

  ret['CVSS2']['Statistics']['Trigram_Total'] = trigram
  ret['CVSS2']['Statistics']['Trigram_Processed'] = proc_trigram
  ret['CVSS2']['Statistics']['Trigram_Perc_Processed'] = proc_trigram / trigram

  ret['CVSS3']['Terms'] = vuln_terms3
  proc_term = 0
  proc_unigram = 0
  proc_bigram = 0
  proc_trigram = 0
  unigram = 0
  bigram = 0
  trigram = 0
  for term in vuln_terms3:
    zeros = contar_espacos(term['term'])
    if term['vectorized']:
      proc_term += 1
      if zeros == 0:
        proc_unigram += 1
      elif zeros == 1:
        proc_bigram += 1
      elif zeros == 2:
        proc_trigram += 1
    if zeros == 0:
      unigram += 1
    elif zeros == 1:
      bigram += 1
    elif zeros == 2:
      trigram += 1
  ret['CVSS3']['Statistics'] = {}
  ret['CVSS3']['Statistics']['Terms_Total'] = len(vuln_terms3)
  ret['CVSS3']['Statistics']['Terms_Processed'] = proc_term
  ret['CVSS3']['Statistics']['Terms_Perc_Processed'] = proc_term / len(vuln_terms3)

  ret['CVSS3']['Statistics']['Unigram_Total'] = unigram
  ret['CVSS3']['Statistics']['Unigram_Processed'] = proc_unigram
  ret['CVSS3']['Statistics']['Unigram_Perc_Processed'] = proc_unigram / unigram

  ret['CVSS3']['Statistics']['Bigram_Total'] = bigram
  ret['CVSS3']['Statistics']['Bigram_Processed'] = proc_bigram
  ret['CVSS3']['Statistics']['Bigram_Perc_Processed'] = proc_bigram / bigram

  ret['CVSS3']['Statistics']['Trigram_Total'] = trigram
  ret['CVSS3']['Statistics']['Trigram_Processed'] = proc_trigram
  ret['CVSS3']['Statistics']['Trigram_Perc_Processed'] = proc_trigram / trigram
  return ret

if __name__ == "__main__":
  package.install_from_path('languages/pt_en.argosmodel')
  txt_pt = "Possibilidade de visualizar mapeamentos de rede através do protocolo NFS sem autenticação. O invasor pode modificar arquivos."
  txt_en = translate.translate(txt_pt, 'pt', 'en')
  
  print('\n\n', 'Texto em Português:', txt_pt, '\n\n', 'Texto em Inglês:', txt_en, '\n\n')
 
  vectorizer2, vectorizer3 = LoadVectorizers()
  models = LoadModels()

  #texto_teste = "Security vulnerability in Apache bRPC <1.5.0 on all platforms allows attackers to execute arbitrary code via ServerOptions::pid_file. An attacker that can influence the ServerOptions pid_file parameter with which the bRPC server is started can execute arbitrary code with the permissions of the bRPC process.  Solution: 1. upgrade to bRPC >= 1.5.0, download link:  https://dist.apache.org/repos/dist/release/brpc/1.5.0/ https://dist.apache.org/repos/dist/release/brpc/1.5.0/  2. If you are using an old version of bRPC and hard to upgrade, you can apply this patch:  https://github.com/apache/brpc/pull/2218 https://github.com/apache/brpc/pull/2218"
  #texto_teste = "A workstation has non blocked USB ports. User can copy files to and from this workstation. This let's the workstation vulnerable to viruses, backdoors and information leak."
  #texto_teste = "possiblity to view network mappings through NFS protocol without authentication."
  #texto_teste = "possiblity to view network mappings through NFS protocol without authentication. The attacker can modify files."
  predicted = Predict(txt_en, vectorizer2, vectorizer3, models)

  pprint.pprint(predicted)
