import pathlib
root = pathlib.Path(__file__).parent
shell = (root/'spec'/'shell.html').read_text(encoding='utf-8')
tokens = (root/'spec'/'tokens.css').read_text(encoding='utf-8')
data = (root/'spec'/'data.js').read_text(encoding='utf-8')
sections = ''.join((root/'sections'/f'{s}.html').read_text(encoding='utf-8') + '\n' for s in ['overview','analyze','trace','forensics'])
assert '/*TOKENS*/' in shell and '<!--SECTIONS-->' in shell and '//DATA' in shell, 'shell markers missing'
out = shell.replace('/*TOKENS*/', tokens, 1).replace('<!--SECTIONS-->', sections, 1).replace('//DATA', data, 1)
(root/'pramaan.html').write_text('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0">' + out + '</body></html>', encoding='utf-8')
print('pramaan.html bytes:', len(out.encode('utf-8')))
