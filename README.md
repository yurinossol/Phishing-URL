# Phishing URL Checker

Ferramenta de linha de comando em Python que analisa uma URL e aponta indícios de que ela pode ser um link de phishing. Ela lê apenas o texto do link, não abre o site nem baixa nada, então é segura de rodar.

Projeto educacional, voltado para o lado defensivo da segurança. Use só em links que você tem autorização para analisar.

## O que ela faz

Você passa uma URL e o programa devolve:

- o hostname e o protocolo do link
- um veredito de risco: `PROVAVELMENTE SEGURO`, `SUSPEITO` ou `PERIGOSO`
- um score numérico
- a lista dos indicadores suspeitos encontrados

## Indicadores analisados

| Indicador | Por que importa |
|---|---|
| Sem HTTPS | conexão sem cadeado, comum em página falsa |
| Host é um IP cru | golpe costuma usar IP no lugar de domínio |
| Palavras sensíveis | termos como login, senha, conta, verificar |
| Excesso de subdomínios | domínio picotado pra confundir a leitura |
| Marca imitada fora do lugar | tipo google no meio de outro domínio |
| Caracteres codificados | %xx escondendo o destino real |
| Hífen no domínio principal | padrão de banco-seguro.com e afins |
| Arroba na URL | truque clássico de redirecionamento |
| Encurtador | esconde para onde o link realmente vai |
| Extensão arriscada | TLDs baratos muito usados em campanha de golpe |
| URL muito longa | tenta cansar quem lê |

Cada indicador soma pontos e o total define o veredito final.

## Como usar

Precisa ter o Python 3 instalado.

Analisar um link digitando na hora:

```
py phishing_url_checker.py
```

Passar o link direto no comando:

```
py phishing_url_checker.py http://site-suspeito.xyz/login
```

Analisar uma lista inteira de uma vez, com um link por linha num arquivo txt:

```
py phishing_url_checker.py -f links.txt
```

No modo de lista ele analisa um por um e mostra um resumo no final com quantos deram perigoso, suspeito e seguro.

## Exemplo

```
py phishing_url_checker.py http://google.com-verificar-conta.xyz/login
```

Esse link acende várias bandeiras: imita a marca google fora do domínio principal, tem palavra sensível, usa extensão arriscada e não tem HTTPS.

## Tecnologia

Python puro, sem bibliotecas externas. Usa só `re`, `sys` e `urllib`, que já vêm instalados com o Python.

## Aviso

Ferramenta feita para fins educacionais e de defesa. Serve para estudar como golpistas montam links falsos e para checar a segurança de links que chegam por email ou mensagem. Não use para nenhum fim que envolva acesso não autorizado.
