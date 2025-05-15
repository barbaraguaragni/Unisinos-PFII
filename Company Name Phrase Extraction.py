from pathlib import Path

def content_analysis(file):
    text = open(file, encoding='utf8').read().lower().split('.')
    return [x.strip() for x in text if contains_keyword(x)]

def contains_keyword(text):
    keywords = ['zscaler']
    return any(word in text for word in keywords)


input_dir = Path(r"E:\Documents\TCC\lemmas\ZS_DB")
output_dir = Path(r"E:\Documents\TCC\phrases extracted\ZS_DB")

for input_file in input_dir.rglob('*.txt'):
    matches = content_analysis(input_file)
    if matches:
        output_file = output_dir / input_file.name
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Results for {input_file.name}:\n")
            for i, match in enumerate(matches, 1):
                f.write(f"{i}. {match}\n")
        print(f"Saved results for {input_file.name} to {output_file}")