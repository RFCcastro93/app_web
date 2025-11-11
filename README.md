
# MVP Plataforma - Contractors e Subcontractors

Este projeto é um MVP (Produto Mínimo Viável) para uma plataforma que conecta **Contractors (empreiteiros)** e **Subcontractors (prestadores de serviço)** através de um sistema de **leilão reverso**, onde o Contractor publica um serviço e os Subcontractors disputam com lances de menor valor.

---

## 🚀 Funcionalidades

### 👷 Contractor
- Cadastro com aprovação
- Publicar novos serviços (com título, descrição, localização e faixa de preço)
- Visualizar serviços publicados
- Receber notificações de lances e do vencedor

### 🧰 Subcontractor
- Cadastro com aprovação
- Visualizar feed de serviços disponíveis
- Dar lances dentro da faixa de preço
- Ser notificado quando ganhar o serviço

### 🧑‍💼 Administrador
- Aprovar cadastros
- Gerenciar serviços
- Visualizar gráficos e estatísticas de uso

---

## ⚙️ Tecnologias

- **Python 3.x**
- **Flask**
- **SQLite**
- **HTML5 / CSS3 / Bootstrap**
- **Jinja2 (Templates)**

---

## 🗂️ Estrutura do Projeto

```
mvp_platform/
│
├── app.py                # Aplicação principal Flask
├── schema.sql            # Estrutura inicial do banco de dados
├── static/
│   ├── style.css         # Arquivo de estilos
│
├── templates/
│   ├── base.html         # Layout principal
│   ├── index.html        # Tela inicial
│   ├── contractor_dashboard.html
│   ├── subcontractor_dashboard.html
│   └── admin_dashboard.html
│
└── README.md
```

---

## 💾 Instalação

### 1️⃣ Clone o repositório ou extraia o ZIP
```bash
unzip mvp_platform.zip
cd mvp_platform
```

### 2️⃣ Crie um ambiente virtual
```bash
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate
```

### 3️⃣ Instale as dependências
```bash
pip install flask
```

### 4️⃣ Inicialize o banco de dados
```bash
python
>>> from app import init_db
>>> init_db()
>>> exit()
```

### 5️⃣ Execute o servidor
```bash
python app.py
```

Acesse em: **http://127.0.0.1:5000**

---

## 📈 Próximos Passos

- Implementar autenticação real (login/senha)
- Envio de notificações por e-mail
- Integração com pagamentos
- Filtros e sistema de busca por categoria e localização
- Dashboard com gráficos reais (Chart.js)

---

Feito com ❤️ por [Robert / Rall Smart Business]
