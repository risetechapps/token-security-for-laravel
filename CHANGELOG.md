# Changelog

Todas as alterações notáveis neste projeto serão documentadas neste arquivo.
O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), e este projeto segue o [Versionamento Semântico](https://semver.org/lang/pt-BR/) (SemVer).

## [2.1.0]

### Security
- **Código TOTP (app autenticador) sem limite de tentativas**: `isValid()` só registrava tentativa errada para código de e-mail/SMS; no TOTP voltava direto do `isValidTotp()`. Quem tinha a senha podia chutar o código de 6 dígitos sem parar. Agora todo tipo de código conta.
- **Limite por destinatário, de qualquer IP**: além do limite por destinatário + IP (5 por 60s), um segundo limite por destinatário (10 por 15 min) freia o chute distribuído entre vários IPs. Configurável em `token-security.limits`.
- Código de 6 dígitos gerado com `random_int` (criptográfico) em vez de `mt_rand`.
- **Código guardado como hash** (HMAC-SHA256 com a `APP_KEY`, amarrado ao destinatário) em vez de texto puro: quem lesse a tabela `tokens` usava os códigos válidos. Códigos emitidos antes da atualização deixam de valer (expiram em 10 min de qualquer forma).

### Fixed
- Tipo `google2fa` (nome usado pelo AuthFlow) era tratado como e-mail/SMS: gravava um código de 6 dígitos que ninguém recebia. Agora é tratado como app autenticador, igual a `totp`.
- **Geração de código falhava por colisão**: a coluna `tokens.token` era `unique` e os códigos usados nunca saem da tabela — com o acúmulo, sortear um código já existente ficava cada vez mais provável (≈11% com 100 mil códigos) e a gravação estourava. Migration remove o `unique` (a busca é por destinatário + hash).

## [2.0.0] - 2026-07-17
- Corrigido parametros e funções obsoletas em php 8.4
- Atualizado Packages
- Update para php 8.4

## [1.2.0] - 2026-01-25
### Added
- Implementado suporte de passar email e sms sem usar um Authenticatable

## [1.1.0] - 2026-01-13
### Added
- Corrigido validação de token


## [1.0.0] - 2026-01-03
### Added
- Lançamento inicial (Primeira versão estável).
