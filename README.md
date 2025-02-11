# Laravel Token Security

## 📌 Sobre o Projeto
O **Laravel token Security** é um package para Laravel validar token de segurança enviado para o email ou celular.

## ✨ Funcionalidades
- 🏷 **Token** código único que vai ser enviado por email ou por sms

---

## 🚀 Instalação

### 1️⃣ Requisitos
Antes de instalar, certifique-se de que seu projeto atenda aos seguintes requisitos:
- PHP >= 8.0
- Laravel >= 10
- Composer instalado

### 2️⃣ Instalação do Package
Execute o seguinte comando no terminal:
```bash
composer require risetechapps/token-security-for-laravel
```

### 3️⃣ Configure seu Controle
```php
  $auth = auth()->user();
  tokenSecurity()->auth($auth)->generateTokenEmail();
```

### 4️⃣ Rodar Migrations
```bash
php artisan migrate
```
---

## 🛠 Contribuição
Sinta-se à vontade para contribuir! Basta seguir estes passos:
1. Faça um fork do repositório
2. Crie uma branch (`feature/nova-funcionalidade`)
3. Faça um commit das suas alterações
4. Envie um Pull Request

---

## 📜 Licença
Este projeto é distribuído sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

💡 **Desenvolvido por [Rise Tech](https://risetech.com.br)**

