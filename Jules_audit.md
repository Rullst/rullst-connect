# Relatório de Auditoria de Segurança — Rullst Connect

**Data da Auditoria:** (Automática)
**Versão Analisada:** v7.0.1+
**Auditor:** Jules

Este documento apresenta os resultados da auditoria de segurança profunda realizada no repositório `rullst-connect`. Embora o relatório `AUDIT.md` existente (v7.0.1) afirme ter corrigido múltiplas falhas de exposição de token e erros silenciosos, uma revisão do código atual (linha a linha) revelou que ainda há áreas críticas que necessitam de correção.

---

## 🎯 Objetivo da Auditoria

O objetivo foi identificar novas vulnerabilidades, garantir o uso adequado de verificações criptográficas (PKCE/OIDC/CSRF), e verificar falhas de gerenciamento de sessão, resiliência do cliente HTTP e tratamento de falhas silenciosas que podem resultar em sequestro de contas ("Phantom Users").

---

## 🔍 Vulnerabilidades Identificadas e Análise

As vulnerabilidades encontradas estão divididas pela sua criticidade.

### 🔴 Criticidade: ALTA (Correção Imediata Recomendada)

#### 1. "Phantom Users" devido a `.unwrap_or_default()` em IDs Críticos
*   **Descrição:** O arquivo `AUDIT.md` afirma que falhas silenciosas de Phantom Users (onde um ID de usuário ausente cria uma conta sem ID ou de string vazia) foram removidas. No entanto, ainda verificamos que a função `.unwrap_or_default()` ou `.unwrap_or(0).to_string()` está ativamente sendo usada para o campo crítico `id` em múltiplos provedores (ex: `GithubProvider`, `LinearProvider`, `AsanaProvider`, `XProvider`, etc). Se a API do provedor mudar, ficar indisponível momentaneamente ou os escopos forem alterados fazendo com que o `id` não retorne, uma string vazia (`""`) ou `"0"` será usada silenciosamente.
*   **Impacto:** Se o banco de dados do cliente não possuir proteções contra IDs vazias, um invasor pode forçar erros de autenticação (ou interceptar tráfego) que causem falhas no parser JSON. Isso resultará em um login bem sucedido no sistema vinculado a um ID genérico (ex: `""`), levando a **Account Takeover (ATO)** ou mesclagem acidental de sessões para milhares de usuários se a falha ocorrer em escala.
*   **Onde:**
    *   `src/providers/github.rs` (Linha 83: `.unwrap_or(0).to_string()`)
    *   `src/providers/linear.rs` (Linha 72: `.unwrap_or_default()`)
    *   `src/providers/x.rs` (Linha 80: `.unwrap_or_default()`)
    *   `src/providers/asana.rs` (Linha 72: `.unwrap_or_default()`)
    *   Entre vários outros listados.

#### 2. Possível DoS via Timers e Retries Infinitos / Não Limitados (HttpClient)
*   **Descrição:** Em `src/client.rs`, o `ReqwestClient` default define um timeout aceitável de 10 segundos, no entanto, para frameworks async, se a resposta do provedor for bloqueada ou a conexão for mantida lenta de propósito no lado do cliente (Slowloris / Tar Pit attack), as execuções de token exchange (que processam buffers via `.text()`) não possuem restrições claras de limite de bytes ou de leituras parciais limitadas pelo tempo total no nível da engine tokio.
*   **Impacto:** Um provedor malicioso (ou um MITM se o DNS for comprometido) retornando um payload gigantesco infinito poderá causar OOM (Out Of Memory) antes da finalização do parser JSON, levando à Negação de Serviço.

### 🟡 Criticidade: MÉDIA (Melhorias de Resiliência)

#### 3. Criptografia OIDC com Fallback Silencioso para `/userinfo`
*   **Descrição:** Nos provedores `GoogleProvider` e `AppleProvider`, o `id_token` JWT é recebido e analisado para validação criptográfica (OIDC). Se houver uma falha ao extrair o `kid`, baixar a JWKS, ou falha real de validação criptográfica (ex: assinatura forjada), o sistema emite um *warning* via `tracing::warn!` e executa um _fallback_ silencioso fazendo uma requisição extra à rota `userinfo`.
*   **Impacto:** Se o token JWT falhar na validação da assinatura, ele DEVE ser rejeitado sumariamente, pois isso indica adulteração ativa. Fazer um _fallback_ é perigoso, pois consome recursos (amplificação de request/rate-limits do provedor) e o invasor pode teoricamente injetar informações. (Nota: Para o Google isso mitiga risco parcial pois o `/userinfo` em si é verificado pelo Access Token do provedor no servidor Google. Contudo, em uma implementação estritamente OIDC, assinar com token adulterado nunca deve ser tolerado.)

#### 4. Ausência de Enforce de PKCE e State em Rotas Opcionais
*   **Descrição:** O método `redirect_url` é a implementação padrão e não embute o `state` nem o `pkce_challenge` obrigatoriamente. O desenvolvedor deve chamar ativamente os métodos builders como `.with_state()` ou as variações `.redirect_url_with_state()`.
*   **Impacto:** Facilita para os desenvolvedores a omissão acidental de proteções de Cross-Site Request Forgery (CSRF).

#### 5. Erro no Manejo Opcional do "Key ID" (`kid`) do Apple
*   **Descrição:** Na verificação de JWT de `AppleProvider`, `let kid = header.kid.unwrap_or_default();` permite o processamento de um token gerado sem `kid` referenciando uma chave JWKS com id de string vazio.
*   **Impacto:** Pode abrir margem para Key Confusion Attacks se o provedor do atacante conseguir enviar uma chave vazia no JWKS local/mock.

### 🟢 Criticidade: BAIXA (Melhores Práticas e Limpeza)

#### 6. Falta de Restrição em `ReqwestClient::new_with_retry`
*   **Descrição:** Se a flag `retry` for utilizada com um valor de `max_retries` extremamente alto via parâmetro no nível do framework, pode causar travamentos prolongados em conexões ruins.
*   **Impacto:** Geração excessiva de logs de erro e retenção de conexões no pool do servidor, afetando performance.

---

## ✅ Resumo das Conclusões

Embora a arquitetura do pacote e as adições recém-implementadas descritas no `AUDIT.md` (como o builder HTTP e PKCE helper) sejam muito robustas e mitiguem grande parte dos ataques clássicos de OAuth2 (vazamento de tokens nas queries e CSRF via Sessions integration), as correções em torno do tratamento do payload JSON (`phantom users`) **foram realizadas de forma incompleta em alguns provedores** e requerem uma refatoração imediata trocando `unwrap_or_default()` por `ok_or_else(|| ConnectError::Provider("Missing ID..."))`.

Recomenda-se iniciar um ciclo de refatoração para abordar principalmente os pontos listados na Criticidade **Alta**.