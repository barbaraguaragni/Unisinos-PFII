import spacy
import os

nlp = spacy.load("en_core_web_sm")

input_dir = r"E:\Documents\TCC\Content Analysis"      
output_dir = r"E:\Documents\TCC\Content Analysis\lemmanized tokens"   

os.makedirs(output_dir, exist_ok=True)

files = [f for f in os.listdir(input_dir) if f.lower().endswith('.txt')]

for filename in files:
    input_path = os.path.join(input_dir, filename)
    output_path = os.path.join(output_dir, filename)
    with open(input_path, 'r', encoding='utf-8') as f:
        text = f.read()
    doc = nlp(text)
    lemmatized_tokens = [token.lemma_ for token in doc]
    lemmatized_text = ' '.join(lemmatized_tokens)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(lemmatized_text)

print(f"Processed files: {files}")