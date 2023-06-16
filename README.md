<h1 align="center">Predição da Severidade e do Tempo de Correção de Vulnerabilidades</h1><br>

<div align="center">
<img src="http://img.shields.io/static/v1?label=STATUS&message=EM%20DESENVOLVIMENTO&color=GREEN&style=for-the-badge"/>
<img src="http://img.shields.io/static/v1?label=LINGUAGEM&message=PYTHON%203.10&color=YELLOW&style=for-the-badge"/>
</div><br>

<h3>1 - Decrição do Projeto:</h3>

<div align="justify">
Em virtude do trabalho desenvolvido no âmbito da dissertação de mestrado, na área de Segurança de Redes, na Universidade Federal Fluminense (UFF) foram avaliados algoritmos, <i>datasets</i> e técnicas de <i>Machine Learning</i> (ML) e <i>Natural Language Processing</i> (NLP) para predição da severidade, <i>base score</i> e métricas do vetor <i>Common Vulnerability Scoring System</i> (CVSS) de uma vulnerabilidade, a partir de sua descrição textual. O treinamento é realizado a partir do repositório do governo dos EUA de dados de gerenciamento de vulnerabilidades, chamado de <i>National Vulnerability Database</i> (NVD), disponibilizado pelo <i>National Institute of Standards and Technology</i> (NIST). Para isso, são propostas três formas de obtenção da severidade de uma vulnerabilidade: (i) severidade como saída do modelo de predição; (ii) severidade em função do <i>base score</i> predito; e (iii) severidade em função do <i>base score</i> calculado a partir das métricas do vetor CVSS. Há, também, um estudo sobre a viabilidade da predição do tempo de correção de vulnerabilidades.
</div>

<h3>2 - Requisitos:</h3>

<div align="justify">
O código deste projeto foi desenvolvido na linguagem Python 3.10. Para utilizar a base de dados completa das versões 2 e/ou 3 do CVSS, pode ser necessário ter mais de 8 GB de memória RAM disponíveis.

Os modelos são treinados a partir de textos em inglês. Logo, a descrição textual usada para realizar as predições devem, também, estar em inglês. No entanto, foi incluída a função de tradução do texto, a fim de permitir que o usuário digite a descrição textual da vulnerabilidade em português. O modelo de tradução PT -> EN pode ser encontrado no site <a href="https://www.argosopentech.com/argospm/index/">https://www.argosopentech.com/argospm/index/</a>.
</div>

<h3>3 - Prova de Conceito:</h3>

<div align="justify">
A prova de conceito foi desenvolvida com base no algoritmo <i>Logistic Regression</i>. Nos testes conduzidos durante o mestrado, o esse algoritmo registrou o segundo melhor desempenho. No entanto, a diferença entre ele o <i>Random Forest</i>, que teve apresentou o melhor resultado, foi próxima a 1 ponto percentual. O que justificou a escolha do segundo melhor algoritmo foi a menor utilização de recursos computacionais (memória RAM e espaço de armazenamento para persistir o modelo) e menor tempo de execução, tanto para treinamento quanto para classificação. Um protótipo foi publicado em: <a href="https://cvss-predict.azurewebsites.net/">https://cvss-predict.azurewebsites.net/</a>.
</div>

<h4>3.1 - Baixar Arquivos CVE/NIST:</h4>

<div align="justify">
Os arquivos do NVD encontram-se no no site <a href="https://nvd.nist.gov/vuln/data-feeds#JSON_FEED">https://nvd.nist.gov/vuln/data-feeds#JSON_FEED</a>. O NIST disponibiliza informações desde 2002. Os arquivos são em formato <i>JavaScript Object Notation</i> (JSON). O <i>script</i> <a href="https://github.com/arsbraga/CVSS-Predict/blob/main/ProofOfConcept/baixar_cve_nist.sh">baixar_cve_nist.sh</a> automatiza o <i>download</i> de todos os arquivos, salvando-os na pasta "<i>dataset</i>", já descompactados. Há um arquivo para cada ano.
</div>

<h4>3.2 - Compilar <i>Datasets</i>:</h4>

<div align="justify">
O programa em Python <a href="https://github.com/arsbraga/CVSS-Predict/blob/main/ProofOfConcept/compilar_dataset.py">compilar_dataset.py</a> tem o objetivo de criar o arquivo "cvss.csv", no formato <i>Comma-Separated Values</i> (CSV), na pasta "<i>dataset</i>". O programa percorrerá todos os arquivos JSON do NVD extraindo as seguintes informações:
<ul>
  <li><b>CVE-ID: </b>Mapeado para o campo "CVE_ID" do arquivo CSV.</li>
  <li><b>Descrição: </b>Mapeado para o campo "CVE_DESC" do arquivo CSV. Também é criado o campo "CVE_DESC_NLP", onde é gravada a descrição após o processamento do algoritmo de NLP.</li>
  <li><b>Métricas do vetor CVSS versão 2:</b></li>
    <ul>
      <li><b><i>Access Vector</i> (AV): </b>Mapeado para o campo "CVSS2_AV" do arquivo CSV. Também é criado o campo "CVSS2_C_AV", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>Requires Local Access</i>: </b>0</li>
          <li><b><i>Local Network Accessible</i>: </b>1</li>
          <li><b><i>Network Accessible</i>: </b>2</li>
        </ul>
      <li><b><i>Access Complexity</i> (AC): </b>Mapeado para o campo "CVSS2_AC" do arquivo CSV. Também é criado o campo "CVSS2_C_AC", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>High</i>: </b>0</li>
          <li><b><i>Medium</i>: </b>1</li>
          <li><b><i>Low</i>: </b>2</li>
        </ul>
      <li><b><i>Authentication</i> (Au): </b>Mapeado para o campo "CVSS2_AU" do arquivo CSV. Também é criado o campo "CVSS2_C_AU", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>Requires Multiple Instances of Authentication</i>: </b>0</li>
          <li><b><i>Requires Single Instance of Authentication</i>: </b>1</li>
          <li><b><i>Requires no Authentication</i>: </b>2</li>
        </ul>
      <li><b><i>Confidentiality Impact</i> (C): </b>Mapeado para o campo "CVSS2_C" do arquivo CSV. Também é criado o campo "CVSS2_C_C", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>None</i>: </b>0</li>
          <li><b><i>Partial</i>: </b>1</li>
          <li><b><i>Complete</i>: </b>2</li>
        </ul>
      <li><b><i>Integrity Impact</i> (I): </b>Mapeado para o campo "CVSS2_I" do arquivo CSV. Também é criado o campo "CVSS2_C_I", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>None</i>: </b>0</li>
          <li><b><i>Partial</i>: </b>1</li>
          <li><b><i>Complete</i>: </b>2</li>
        </ul>
      <li><b><i>Availability Impact</i> (A): </b>Mapeado para o campo "CVSS2_A" do arquivo CSV. Também é criado o campo "CVSS2_C_A", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>None</i>: </b>0</li>
          <li><b><i>Partial</i>: </b>1</li>
          <li><b><i>Complete</i>: </b>2</li>
        </ul>
    </ul>
  <li><b>Métricas do vetor CVSS versão 3:</b></li>
    <ul>
      <li><b><i>Attack Vector</i> (AV): </b>Mapeado para o campo "CVSS3_AV" do arquivo CSV. Também é criado o campo "CVSS3_C_AV", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>Physical Interaction</i>: </b>0</li>
          <li><b><i>Local Access</i>: </b>1</li>
          <li><b><i>Adjacent Network Accessible</i>: </b>2</li>
          <li><b><i>Network Accessible</i>: </b>3</li>
        </ul>
      <li><b><i>Attack Complexity</i> (AC): </b>Mapeado para o campo "CVSS3_AC" do arquivo CSV. Também é criado o campo "CVSS3_C_AC", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>High</i>: </b>0</li>
          <li><b><i>Low</i>: </b>1</li>
        </ul>
      <li><b><i>Privileges Required</i> (PR): </b>Mapeado para o campo "CVSS3_PR" do arquivo CSV. Também é criado o campo "CVSS3_C_PR", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>High</i>: </b>0</li>
          <li><b><i>Low</i>: </b>1</li>
          <li><b><i>None</i>: </b>2</li>
        </ul>
      <li><b><i>User Interaction</i> (UI): </b>Mapeado para o campo "CVSS3_UI" do arquivo CSV. Também é criado o campo "CVSS3_C_UI", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>Required</i>: </b>0</li>
          <li><b><i>None</i>: </b>1</li>
        </ul>
      <li><b><i>Scope</i> (S): </b>Mapeado para o campo "CVSS3_S" do arquivo CSV. Também é criado o campo "CVSS3_C_S", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>Unchanged</i>: </b>0</li>
          <li><b><i>Changed</i>: </b>1</li>
        </ul>
      <li><b><i>Confidentiality Impact</i> (C): </b>Mapeado para o campo "CVSS3_C" do arquivo CSV. Também é criado o campo "CVSS3_C_C", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>None</i>: </b>0</li>
          <li><b><i>Low</i>: </b>1</li>
          <li><b><i>High</i>: </b>2</li>
        </ul>
      <li><b><i>Integrity Impact</i> (I): </b>Mapeado para o campo "CVSS3_I" do arquivo CSV. Também é criado o campo "CVSS3_C_I", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>None</i>: </b>0</li>
          <li><b><i>Low</i>: </b>1</li>
          <li><b><i>High</i>: </b>2</li>
        </ul>
      <li><b><i>Availability Impact</i> (A): </b>Mapeado para o campo "CVSS3_A" do arquivo CSV. Também é criado o campo "CVSS3_C_A", onde é gravado o código que será processado pelos algoritmos de ML, conforme a seguinte correlação:</li>
        <ul>
          <li><b><i>None</i>: </b>0</li>
          <li><b><i>Low</i>: </b>1</li>
          <li><b><i>High</i>: </b>2</li>
        </ul>
    </ul>
</ul>
Ressalta-se que os campos, no arquivo CSV, são delimitados pelo caracter trema (&uml;).
</div>

<h4>3.3 - Validação Cruzada:</h4>

<div align="justify">
Inicialmente, a partir do arquivo "cvss.csv", o programa <a href="https://github.com/arsbraga/CVSS-Predict/blob/main/ProofOfConcept/cve_cross_validation.py">cve_cross_validation.py</a> cria dois <i>datasets</i>: (i) somente vulnerabilidades que contenham análises baseadas na versão 2 do CVSS, salva no arquivo "cvss_v2.csv", na pasta "<i>dataset</i>"; e (ii) somente vulnerabilidades que contenham análises baseadas na versão 3 do CVSS, salva no arquivo "cvss_v3.csv", na pasta "<i>dataset</i>". Para cada métrica de cada um desses dois <i>datasets</i>, o programa seleciona cinco conjuntos de treinamento e validação, denominados <i>folds</i>. Para cada um desses cinco <i>folds</i> o programa treina o modelo a partir do conjunto de treinamento e faz a classificação a partir do conjunto de validação. É criado o arquivo validacao_cruzada.csv, na pasta "resultados", que armazenará os indicadores de desempenho de cada <i>fold</i> e a média de todos os <i>fold</i> em cada métrica do vetor CVSS. Os indicadores de desempenho compilados são:
  <ul>
    <li><b>Acurácia</b>: para problemas de classificação em que existem múltiplas classes, representa percentual em que a predição das classes é correta, ou seja, é exatamente igual à real;</li>
    <li><b><i>Precision</i></b>: é a razão <b><i>(vp / vp + fp)</i></b>, onde <b><i>vp</i></b> é o número de verdadeiros positivos e <b><i>fp</i></b> o número de falsos positivos. <i>Precision</i> é a capacidade do classificador não rotular como positiva uma amostra que é negativa. Para problemas de classificação em que existem múltiplas classes, representa a média ponderada do <i>precision</i> de cada classe. O melhor valor é 1 e o pior valor é 0;</li>
    <li><b><i>Recall</i></b>: representa a razão <b><i>(vp / vp + fn)</i></b>, onde <b><i>vp</i></b> é o número de verdadeiros positivos e <b><i>fn</i></b> o número de falsos negativos. O <i>recall</i> é a habilidade do classificador em encontrar todas as amostras positivas. Para problemas de classificação em que existem múltiplas classes, representa a média ponderada do <i>recall</i> de cada classe. O melhor valor é 1 e o pior valor é 0; e</li>
    <li><b><i>F1 score</i></b>: é a média harmônica de <i>precision</i> e <i>recall</i>. No caso problemas de classificação em que existem múltiplas classes, representa a média ponderada do <i>F1 score</i> de cada classe. O melhor valor é 1 e o pior valor é 0.</li>
  </ul>
Para os indicadores de desempenho <i>precision</i>, <i>recall</i> e <i>F1 score</i>, são aplicadas três metodologias de cálculo:
  <ul>
    <li><b><i>Micro</i></b>: calcula os indicadores de desempenho globalmente, contando o total de verdadeiros positivos, falsos negativos e falsos positivos;</li>
    <li><b><i>Macro</i></b>: calcula os indicadores de desempenho para cada classe e encontra sua média não ponderada. Não levando em consideração o desequilíbrio entre as classes; e</li>
    <li><b><i>Weighted</i></b>: calcula os indicadores de desempenho para cada classe e encontra sua média ponderada pelo suporte (o número de instâncias verdadeiras para cada classe). Equivalente ao '<i>Macro</i>', considerando o desequilíbrio entre as classes. O <i>recall</i> ponderado é igual a Acurácia.</li>
  </ul>
Esse programa se limita a testar a estabilidade e o desempenho dos modelos.
</div>

<h4>3.4 - Criação dos Modelos (Aprendizado):</h4>

<div align="justify">
O programa <a href="https://github.com/arsbraga/CVSS-Predict/blob/main/ProofOfConcept/cve_ia.py">cve_ia.py</a> é responsável por criar os modelos através do treinamento com base nos <i>datasets</i> gerados, conforme descrito anteriormente. Além desses <i>datasets</i>, também há o <i>dataset</i> relativo às aplicações de comunicação, armazenado no arquivo <a href="https://github.com/arsbraga/CVSS-Predict/blob/main/ProofOfConcept/dataset/cve_multimidia_patching_time.csv">cve_multimidia_patching_time.csv</a>, na pasta "<i>dataset</i>". Ele contém informações sobre o tempo necessário para correçao das vulnerabilidades, coletadas manualmente nos site de <i>security advisor</i> dos fabricantes.
Nesse ponto o programa converte as descrições das vulnerabilidades em uma matriz de <i>features</i> TF-IDF. A partir de então, já é possível efetuar o treinamento, criando os modelos que serão utilizados para fazer as predições, conforme a seguir:
  <ul>
    <li><b>"Vetorizador"</b>: São criados três "vetorizadores" (ou conversor de descrições de vulnerabilidades em matriz de <i>features</i> TF-IDF). Um para a vesão 2 do CVSS ("vectorizer_CVSS2.tfidf"), um para a vesão 3 do CVSS ("vectorizer_CVSS3.tfidf") e um para as aplicações de comunicação ("vectorizer_PT.tfidf"). Todos esses arquivos são salvos na pasta "modelos";</li>
    <li><b>Modelos</b>: São criados os modelos para todas as métricas das vesões 2 e 3 do CVSS, baseados no algoritmo <i>Logistic Regression</i>, e o modelo para predição do tempo de correção de vulnerabilidade, baseado no algoritmo <i>Support Vector Machine</i> (SVM):</li>
      <ul>
        <li><b>CVSS versão 2</b>: Para a versão 2 do CVSS são criados os seguintes modelos, na pasta "modelos": "classifier_CVSS2_C_AC.model", "classifier_CVSS2_C_A.model", "classifier_CVSS2_C_AU.model", "classifier_CVSS2_C_AV.model", "classifier_CVSS2_C_C.model" e "classifier_CVSS2_C_I.model";</li>
        <li><b>CVSS versão 3</b>: Para a versão 3 do CVSS são criados os seguintes modelos, na pasta "modelos": "classifier_CVSS3_C_AC.model", "classifier_CVSS3_C_A.model", "classifier_CVSS3_C_AV.model", "classifier_CVSS3_C_C.model", "classifier_CVSS3_C_I.model", "classifier_CVSS3_C_PR.model", "classifier_CVSS3_C_S.model" e "classifier_CVSS3_C_UI.model"; e</li>
        <li><b>Tempo de Correção de Vulnerabilidades</b>: Para a predição do tempo de correção de vulnerabilidades é criado o modelo "classifier_PT.model", na pasta "modelos".</li>
      </ul>
  </ul>
</div>

<h4>3.5 - Classificação (Predição):</h4>

<div align="justify">
O arquivo <a href="https://github.com/arsbraga/CVSS-Predict/blob/main/ProofOfConcept/cve_classify.py">cve_classify.py</a> é uma biblioteca que contém diversas funções para apoiar aplicações na predição das métricas do vetor CVSS, do <i>base score</i>, da severidade e do tempo de correção de uma vulnerabilidade. Em suma, as seguintes funções estão presentes na biblioteca:
  <ul>
    <li><b>Carregar "Vetorizadores" e Modelos</b>: Essas funções carregam os arquivos em memória;</li>
    <li><b>Tratar a Descrição Textual da Vulnerabilidade</b>: Processa a descrição textual de uma vulnerabilidade através de algoritmos de NLP;</li>
    <li><b>"Vetorizador"</b>: Converte a descrição textual de uma vulnerabilidade em vetor de <i>features</i>, através da técnica TF-IDF. Essa função também retorna os termos (unigramas, bigramas ou trigramas) presentes na descrição, com o <i>flag</i> para indicar se o termo foi ou não processado pelo classificador;</li>
    <li><b>Predição</b>: Esta função faz a predição de todas as métricas do vetor CVSS nas versões 2 e 3. Para cada classe, de cada métrica, é incluída a probalidade. A partir da classe com a maior probabilidade, de cada métrica, é calculado o <i>base score</i> e a severidade. Com base na documentação do CVSS, um texto é construído para descrever as predições obtidas. Para auxiliar o usuário na elaboração da descrição textual, esta função também compila as estatísticas referentes ao processamento dos unigramas, bigramas, trigramas e de todos os termos, em geral;</li>
  </ul>
</div>

<h4>3.6 - Interface Web:</h4>

<div align="justify">
Texto.
</div>

<h3>4 - Limitações</h3>

<div align="justify">
Texto.
</div>
