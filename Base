#!/usr/bin/env python3
"""
PHISHING URL CHECKER
Ferramenta educacional de análise de URLs.
Use só em links que você tem autorização para analisar.
"""

import re
import sys
from urllib.parse import urlparse, unquote

BANNER = r"""
=========================================
       </> PHISHING URL CHECKER >
=========================================
"""

# Palavras que golpistas usam pra parecer legítimo
PALAVRAS_SUSPEITAS = [
    "login", "signin", "account", "verify", "secure", "update",
    "banking", "confirm", "password", "senha", "conta", "atualizar",
    "verificar", "seguranca", "premio", "desbloqueio",
]

# Marcas comumente imitadas em golpes
MARCAS = [
    "google", "facebook", "instagram", "whatsapp", "netflix", "apple",
    "microsoft", "amazon", "nubank", "itau", "bradesco", "santander",
    "caixa", "mercadolivre", "correios", "gov", "paypal", "picpay",
]

# Encurtadores que escondem o destino real
ENCURTADORES = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "encurtador.com.br",
]

# TLDs baratos muito usados em campanha de golpe
TLDS_ARRISCADOS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".work", ".zip", ".mov", ".loan", ".country",
]


def normalize_url(url: str) -> str:
    """Coloca um esquema quando a pessoa digita só o domínio."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def is_ipv4(hostname: str) -> bool:
    """Checagem básica de IPv4."""
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if not re.fullmatch(pattern, hostname):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in hostname.split("."))
    except ValueError:
        return False


def analyze_url(url: str) -> dict:
    """Roda todos os indicadores e devolve o resultado."""
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    caminho = parsed.path.lower()
    url_inteira = url.lower()

    indicadores = []
    score = 0

    # 1. Sem HTTPS
    if parsed.scheme != "https":
        indicadores.append("Nao usa HTTPS (conexao sem cadeado)")
        score += 2

    # 2. Host e um IP cru
    if is_ipv4(hostname):
        indicadores.append("Endereco e um IP cru, nao um dominio")
        score += 3

    # 3. Palavras sensiveis
    achadas = [p for p in PALAVRAS_SUSPEITAS if p in url_inteira]
    if achadas:
        indicadores.append(f"Palavras sensiveis: {', '.join(achadas[:5])}")
        score += len(achadas)

    # 4. Excesso de subdominios
    if hostname.count(".") >= 3:
        indicadores.append("Muitos subdominios (dominio picotado)")
        score += 2

    # 5. Marca imitada fora do dominio principal
    partes = hostname.split(".")
    dominio_base = ".".join(partes[-2:]) if len(partes) >= 2 else hostname
    for marca in MARCAS:
        if marca in hostname and marca not in dominio_base:
            indicadores.append(f"Imita a marca '{marca}' no lugar errado da URL")
            score += 3
            break

    # 6. Caracteres codificados escondendo algo
    if "%" in url and unquote(url) != url:
        indicadores.append("URL tem caracteres codificados (%xx)")
        score += 2

    # 7. Hifen no dominio (tipo banco-seguro.com)
    if "-" in dominio_base:
        indicadores.append("Hifen no dominio principal (comum em golpe)")
        score += 1

    # 8. Arroba na URL (truque de redirecionamento)
    if "@" in url:
        indicadores.append("Tem '@' na URL (esconde o destino real)")
        score += 3

    # 9. Encurtador
    if any(e in hostname for e in ENCURTADORES):
        indicadores.append("Usa encurtador (destino real fica escondido)")
        score += 2

    # 10. TLD arriscado
    if any(hostname.endswith(t) for t in TLDS_ARRISCADOS):
        indicadores.append("Extensao de dominio comum em campanha de golpe")
        score += 2

    # 11. URL muito longa
    if len(url) > 90:
        indicadores.append("URL muito longa (tenta cansar/enganar a leitura)")
        score += 1

    # Classifica o risco pelo score
    if score >= 7:
        risco = "PERIGOSO"
    elif score >= 3:
        risco = "SUSPEITO"
    else:
        risco = "PROVAVELMENTE SEGURO"

    return {
        "url": url,
        "hostname": hostname,
        "protocolo": parsed.scheme.upper(),
        "risco": risco,
        "score": score,
        "indicadores": indicadores,
    }


def imprimir(resultado: dict) -> None:
    print("\n----------- RESULTADO -----------")
    print(f"URL       : {resultado['url']}")
    print(f"Hostname  : {resultado['hostname']}")
    print(f"Protocolo : {resultado['protocolo']}")
    print(f"Risco     : {resultado['risco']}")
    print(f"Score     : {resultado['score']}")
    print("\nIndicadores:")
    if resultado["indicadores"]:
        for item in resultado["indicadores"]:
            print(f"  [!] {item}")
    else:
        print("  [+] Nenhum indicador suspeito encontrado")
    print("\n[+] Analise concluida.\n")


def analisar_arquivo(caminho: str) -> None:
    """Le um arquivo txt (um link por linha) e analisa todos."""
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            linhas = [linha.strip() for linha in f if linha.strip()]
    except FileNotFoundError:
        print(f"[x] Arquivo nao encontrado: {caminho}")
        return

    if not linhas:
        print("[x] O arquivo esta vazio.")
        return

    resumo = {"PERIGOSO": 0, "SUSPEITO": 0, "PROVAVELMENTE SEGURO": 0}

    print(f"\nAnalisando {len(linhas)} link(s)...\n")
    for url in linhas:
        resultado = analyze_url(url)
        imprimir(resultado)
        resumo[resultado["risco"]] += 1

    print("=========== RESUMO GERAL ===========")
    print(f"  Perigosos            : {resumo['PERIGOSO']}")
    print(f"  Suspeitos            : {resumo['SUSPEITO']}")
    print(f"  Provavelmente seguros: {resumo['PROVAVELMENTE SEGURO']}")
    print(f"  Total analisado      : {len(linhas)}")
    print("====================================\n")


def main():
    print(BANNER)

    # Modo lote: python phishing_url_checker.py -f lista.txt
    if len(sys.argv) > 2 and sys.argv[1] in ("-f", "--file"):
        analisar_arquivo(sys.argv[2])
        return

    # Modo link unico pela linha de comando
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Digite a URL pra analisar: ")

    resultado = analyze_url(url)
    imprimir(resultado)


if __name__ == "__main__":
    main()
