# ⚡ FlowCast Planner

Planner de produção de conteúdo com login por usuário.
Cada pessoa cria sua conta e tem seus próprios canais, prompts e tarefas.

---

## 🚀 Deploy no Railway (Passo a Passo)

### 1. Crie uma conta no GitHub
- Acesse https://github.com e crie uma conta (se ainda não tiver)

### 2. Crie um repositório no GitHub
- Clique em **"New repository"** (botão verde)
- Nome: `flowcast-planner`
- Marque **"Public"**
- Clique em **"Create repository"**

### 3. Suba os arquivos
- Na página do repositório, clique em **"uploading an existing file"**
- Arraste TODOS os arquivos desta pasta (app.py, templates/, etc.)
- Clique em **"Commit changes"**

### 4. Deploy no Railway
- Acesse https://railway.app e faça login com sua conta GitHub
- Clique em **"New Project"**
- Escolha **"Deploy from GitHub Repo"**
- Selecione o repositório `flowcast-planner`
- Railway vai detectar automaticamente que é Python e fazer o deploy
- Quando terminar, clique em **"Generate Domain"** para ter um link público

### 5. Configurar variável de ambiente (importante!)
- No Railway, vá em **Settings > Variables**
- Adicione: `SECRET_KEY` = (clique em "Generate" ou coloque qualquer texto longo aleatório)

### 6. Pronto! 🎉
- Compartilhe o link com seus amigos
- Cada um cria sua conta e acessa seus próprios dados

---

## 💻 Rodar Local

```bash
pip install flask
python app.py
```

Acesse: http://localhost:5000

---

## 📁 Estrutura

```
flowcast-deploy/
├── app.py              # Backend (Flask + SQLite + Auth)
├── requirements.txt    # Dependências
├── Procfile            # Config Railway
├── railway.json        # Config Railway
├── nixpacks.toml       # Config build
├── .gitignore
├── README.md
└── templates/
    ├── index.html      # Dashboard principal
    ├── login.html      # Página de login
    └── register.html   # Página de cadastro
```

## 🔑 Funcionalidades

- ✅ Login e cadastro com senha criptografada
- ✅ Cada usuário tem dados isolados (canais, prompts, tarefas)
- ✅ 📅 Fluxo — tarefas automáticas baseadas nos canais
- ✅ 📺 Canais — criar, editar, remover com ícone/cor/frequência
- ✅ 📄 Prompts — biblioteca organizada por canal
- ✅ 💾 SQLite — persistência sem configuração extra
