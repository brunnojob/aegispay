# AegisPay — gateway de pagamentos com foco em segurança

Autoria: brunnojob / brunnodev.store.

## Objetivo

Construir uma camada própria para receber intenções de pagamento, integrar processadores e controlar autorização, criptografia, duplicidade, confirmação e auditoria. O gateway terá código e regras próprios; bancos/processadores continuarão responsáveis pelos serviços que contratarmos para movimentar os recursos.

## Entrega inicial

API funcional em Node.js 24, SQLite persistente, chaves de API por lojista, tokens sintéticos cifrados com AES-256-GCM, idempotência transacional, eventos assinados, deduplicação persistente e trilha de auditoria com HMAC. Valores em centavos e moeda BRL.

O pacote inclui teste do fluxo completo e testes de segurança. Nenhuma transação real é realizada. As confirmações do exemplo são enviadas por um simulador que possui o segredo de assinatura.

## Direção do projeto

1. Sandbox local e testes de segurança: implementados nesta versão.
2. Escolha de processador e integração de checkout/cartão tokenizado e Pix em ambiente de testes.
3. Conciliação, estornos, expiração e tratamento de falhas ou resultados incertos.
4. PostgreSQL, gestão e rotação de chaves, monitoramento e controle de acesso operacional.
5. Revisão independente de segurança e avaliação dos requisitos aplicáveis antes de operar com dinheiro real.

Sigilo significa minimizar a coleta, restringir o acesso e proteger dados armazenados e transmitidos. Não significa anonimato perante processadores/bancos nem garantia de invulnerabilidade. Não há certificação PCI DSS ou conformidade LGPD atestada por este projeto.

## Executar

Instale Node.js 24.15 ou superior na linha 24.x, abra um terminal na pasta e execute:

```sh
npm run setup
npm test
npm start
```

Em outro terminal, na mesma pasta:

```sh
npm run demo
```

O resultado mostra a criação, a tentativa repetida sem nova cobrança e a confirmação simulada. Não envie CPF, cartão, CVV ou credenciais bancárias.

## Repositório

Código: https://github.com/brunnojob/aegispay

Para desenvolver localmente:

```sh
git clone https://github.com/brunnojob/aegispay.git
cd aegispay
npm run setup
npm test
npm start
```

O `.gitignore` exclui `.env` e bancos locais. O arquivo de configuração contém segredos; mantenha-o apenas na máquina de desenvolvimento.
