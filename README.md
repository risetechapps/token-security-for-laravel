
# Laravel Token Security

## 📌 Sobre o Projeto

**Laravel Token Security** é um pacote para Laravel que permite a geração e validação de **tokens de segurança** enviados por e-mail ou SMS. Ideal para autenticação em duas etapas (2FA), verificação de identidade, ou confirmações sensíveis dentro da aplicação.

## ✨ Funcionalidades

- 🔐 **Token de Segurança**: código único e temporário gerado para validação
- 📧 **Envio via E-mail**
- 📱 **Envio via SMS**
- ✅ **Validação de Token**
- 🕐 **Token com tempo de expiração configurável**

---

## 🚀 Instalação

### 1️⃣ Requisitos

Certifique-se de que seu projeto atende aos seguintes requisitos:

- PHP >= 8.3  
- Laravel >= 12  
- Composer instalado  

### 2️⃣ Instalação do Pacote

Execute o comando abaixo no terminal:

```bash
  composer require risetechapps/token-security-for-laravel
```

### 3️⃣ Rodar as Migrations

```bash
  php artisan migrate
```

### 4️⃣ Gerar e Enviar Token

Você pode gerar um token vinculado a um usuário autenticado e enviá-lo por e-mail ou SMS:

```php
// Gerar e enviar por e-mail
tokenSecurity()
    ->auth(auth()->user())
    ->generateTokenEmail();

// Gerar e enviar por SMS
tokenSecurity()
    ->auth(auth()->user())
    ->generateTokenSMS();
```

---

## ✅ Exemplo: Geração e Validação de Token SMS

```php
public function confirmCellphone(Request $request): JsonResponse
{
    try {

        $model = new Authentication();
        $auth = $model->find($request->input('id'));

        // Gera o token de segurança e envia por e-mail
        // O token será enviado para o e-mail do usuário autenticado
        // Certifique-se de que o usuário tenha um e-mail válido
        // e que o serviço de envio de e-mails esteja configurado corretamente
        // passe token e o metodo de confirmacao via header
        // exemplo: X-OTP-Operation com o valor 'email' ou 'sms' para indicar o tipo de confirmação
        // exemplo: X-OTP-Code: com codigo de confirmação digitado pelo usuário
        // //caso o token seja válido, a função não lançará exceção e continuará a execução
        // caso o token seja inválido, a função lançará uma exceção HttpResponseException: abort(response()->json($data, 418));
        // caso o token seja expirado, a função lançará uma exceção HttpResponseException: abort(response()->json($data, 418));
        tokenSecurity()->auth($auth)->generateTokenSms();

        return response()->json(['success' => true]);

    } catch (HttpResponseException $e) {
        throw $e;
    } catch (\Exception $exception) {
      
        return response()->json(['success' => false]);
    }
}
```

## ✅ Exemplo: Geração e Validação de Token Email

```php
public function confirmEmail(Request $request): JsonResponse
{
    try {

        $model = new Authentication();
        $auth = $model->find($request->input('id'));
        
        // Gera o token de segurança e envia por e-mail
        // O token será enviado para o e-mail do usuário autenticado
        // Certifique-se de que o usuário tenha um e-mail válido
        // e que o serviço de envio de e-mails esteja configurado corretamente
        // passe token e o metodo de confirmacao via header
        // exemplo: X-OTP-Operation com o valor 'email' ou 'sms' para indicar o tipo de confirmação
        // exemplo: X-OTP-Code: com codigo de confirmação digitado pelo usuário
        // //caso o token seja válido, a função não lançará exceção e continuará a execução
        // caso o token seja inválido, a função lançará uma exceção HttpResponseException: abort(response()->json($data, 418));
        // caso o token seja expirado, a função lançará uma exceção HttpResponseException: abort(response()->json($data, 418));
        tokenSecurity()->auth($auth)->generateTokenEmail();

        return response()->json(['success' => true]);

    } catch (HttpResponseException $e) {
        throw $e;
    } catch (\Exception $exception) {
      
        return response()->json(['success' => false]);
    }
}
```

---

## 🛠 Contribuindo

Contribuições são bem-vindas! Para contribuir:

1. Faça um **fork** do repositório  
2. Crie uma **branch**: `feature/nova-funcionalidade`  
3. Faça **commit** das suas alterações  
4. Envie um **Pull Request**

---

## 📜 Licença

Este projeto é licenciado sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.

---

💡 **Desenvolvido por [Rise Tech](https://risetech.com.br)**
