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
Os arquivos do NVD encontram-se no no site <a href="https://nvd.nist.gov/vuln/data-feeds#JSON_FEED">https://nvd.nist.gov/vuln/data-feeds#JSON_FEED</a>. O NIST disponibiliza informações desde 2002. Os arquivos são em formato <i>JavaScript Object Notation</i> (JSON). O <i>script</i> <a href="https://github.com/arsbraga/CVSS-Predict/blob/main/ProofOfConcept/baixar_cve_nist.sh">baixar_cve_nist.sh</a>
</div>

<h4>3.2 - Compilar Datasets:</h4>

<div align="justify">
Texto.
</div>

<h4>3.3 - Validação Cruzada:</h4>

<div align="justify">
Texto.
</div>

<h4>3.4 - Criação dos Modelos (Aprendizado):</h4>

<div align="justify">
Texto.
</div>

<h4>3.5 - Interface Web e Classificação (Predição):</h4>

<div align="justify">
Texto.
</div>

<h3>4 - Datasets</h3>

<div align="justify">
Texto.
</div>

<h3>5 - Limitações</h3>

<div align="justify">
Texto.
</div>
