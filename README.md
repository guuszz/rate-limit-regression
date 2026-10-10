# Rate Limit Regression

Pequeno teste de regressão para uma pergunta prática de AppSec: uma rota de ativação interrompe tentativas repetidas e informa quando a pessoa pode tentar de novo?

O cenário é inteiramente sintético, usa apenas `127.0.0.1` e não incorpora dados de aplicações ou relatórios privados. O problema que o projeto explora é a regressão de controles de tentativa após mudanças em fluxos sensíveis; o MVP oferece uma forma pequena e repetível de testar uma API de demonstração antes de depender de uma verificação manual.

## Por que esse problema importa

Limitar tentativas é uma prática reconhecida para reduzir ataques de adivinhação online: o NIST SP 800-63B-4 descreve controles de rate limiting/throttling para verificadores de autenticação, e a OWASP REST Assessment recomenda testar throttling em endpoints de autenticação, token e recuperação de conta ([NIST, seção 3.2.2](https://pages.nist.gov/800-63-4/sp800-63b.html#rate-limiting-throttling); [OWASP REST Assessment](https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html#rate-limiting-and-throttling-assessment)). Essas referências sustentam a relevância do controle; não demonstram demanda pelo formato deste protótipo. A utilidade operacional e os critérios de aceitação ainda precisam ser discutidos com profissionais que mantêm APIs.

## O que faz

- Inicia uma API de demonstração em loopback, com implementação deliberadamente corrigida ou sem limitador para comparar resultados.
- Envia no máximo oito solicitações com credenciais fictícias.
- Considera `429` acompanhado de `Retry-After` como sinal esperado de bloqueio; a ausência do bloqueio resulta em `FAIL`.
- Recusa HTTPS, nomes de host, IPs de rede, credenciais embutidas e redirecionamentos; a conexão é direta e ignora proxies configurados no ambiente.

Isto é um MVP didático, não uma validação de produto de terceiros nem prova de que um limitador está completo. Limites distribuídos, vários nós, identidades artificiais e abuso de contas reais exigem controles e testes próprios.

## Instalar e rodar a demonstração

Requer Python 3.11+ e apenas a biblioteca padrão.

Instalação local:

```powershell
python -m pip install --editable .
```

Terminal 1 — versão corrigida:

```powershell
$env:PYTHONPATH = "src"
python -m ratelimit_regression.fixture
```

Terminal 2 — teste local:

```powershell
$env:PYTHONPATH = "src"
python -m ratelimit_regression.probe http://127.0.0.1:8765/activate
```

Resultado esperado:

```json
{"attempts_sent": 4, "blocked_at": 4, "http_statuses": [401, 401, 401, 429], "result": "PASS"}
```

Para simular a configuração sem limitação, iniciar o fixture com `--vulnerable`. O mesmo teste termina em `FAIL` após oito requisições sintéticas.

## Testes

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

O conjunto cobre janela e recuperação, separação de identidade, recusa de endereços não locais e demonstração corrigida versus vulnerável.

O GitHub Actions executa a mesma suíte em push e pull request.

## Próximo passo

Antes de ampliar a ferramenta, conversar com duas pessoas que mantenham APIs para descobrir se já têm testes semelhantes, o que lhes falta e qual seria um critério de aceitação útil. Um reporte isolado motiva a pergunta; não prova demanda de mercado.

## Limites

- O limitador em memória é apenas uma fixture de teste, não deve ser adotado como implementação de produção.
- O probe aceita apenas endereços IP literais de loopback (`127.0.0.1` ou `::1`), não segue redirecionamentos, ignora proxies configurados e não aceita destinos remotos.
- Não guarda corpos de resposta, tokens ou credenciais reais.
