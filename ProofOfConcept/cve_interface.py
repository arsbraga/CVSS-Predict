# Imports
import sys
import pickle
import numpy as np
import cve_classify 
from argostranslate import package, translate
from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)

app.config['SECRET_KEY'] = 'e21463b3078424d8d28544a7c754fcf3'

class VulnerabilityForm_en(FlaskForm):
  description_en = TextAreaField('Vulnerability Description (EN)', validators=[DataRequired()])
  send = SubmitField('send')
  
class VulnerabilityForm_pt(FlaskForm):
  description_pt = TextAreaField('Vulnerability Description (PT)', validators=[DataRequired()])
  send = SubmitField('send')
  
@app.context_processor
def utility_processor():
  def src_lst_dict(terms, term):
    return next(item for item in terms if item['term'] == term)
  return dict(src_lst_dict=src_lst_dict)

@app.route('/')
def index():
  vulnerability_form_en = VulnerabilityForm_en()
  vulnerability_form_pt = VulnerabilityForm_pt()
  return render_template('index.html', vulnerability_form_en=vulnerability_form_en, vulnerability_form_pt=vulnerability_form_pt)

@app.route('/cvss_predict_en', methods=['GET', 'POST'])
def cvss_predict_en():
  vulnerability_form_en = VulnerabilityForm_en()
  if vulnerability_form_en.validate_on_submit() and ('send' in request.form):
    vectorizer2, vectorizer3, vectorizerPT = cve_classify.LoadVectorizers()
    models = cve_classify.LoadModels()
    predict_vuln = cve_classify.Predict(vulnerability_form_en.description_en.data, vectorizer2, vectorizer3, vectorizerPT, models)
    return render_template('cvss_predict_en.html', description_en=vulnerability_form_en.description_en.data, predict_vuln=predict_vuln)
  else:
    return "An error ocurred. Please, try again."

@app.route('/cvss_predict_pt', methods=['GET', 'POST'])
def cvss_predict_pt():
  vulnerability_form_pt = VulnerabilityForm_pt()
  if vulnerability_form_pt.validate_on_submit() and ('send' in request.form):
    package.install_from_path('languages/pt_en.argosmodel')
    vectorizer2, vectorizer3, vectorizerPT = cve_classify.LoadVectorizers()
    models = cve_classify.LoadModels()
    txt_en = translate.translate(vulnerability_form_pt.description_pt.data, 'pt', 'en')
    predict_vuln = cve_classify.Predict(txt_en, vectorizer2, vectorizer3, vectorizerPT, models)
    return render_template('cvss_predict_pt.html', description_en=txt_en, description_pt=vulnerability_form_pt.description_pt.data, predict_vuln=predict_vuln)
  else:
    return "An error ocurred. Please, try again."
  
print("Carregando pacote de idiomas PT -> EN")
package.install_from_path('languages/pt_en.argosmodel')
vectorizer2, vectorizer3, vectorizerPT = cve_classify.LoadVectorizers()
models = cve_classify.LoadModels()
app.run(debug=True)
