# Portal
 Encrypted Webserver with Dynamic Pages


# 🔐 Flask Encrypted Template

A lightweight, secure Flask-based template using **AES-256** and **RSA-4096** encryption. This project provides a dynamic web framework with built-in encryption tools for secure data handling and user communication.

---

## ✨ Features

* 🔑 **AES-256 GCM + RSA-4096** Encryption System
* 🧰 Built-in Key Generator for RSA and AES
* 🌐 Flask Web App with Dynamic Page System (Jinja2 templates)
* 📦 Easy to run on Windows or Linux
* 📁 Organized, minimal template for quick project startup

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/flask-encrypted-template.git
cd flask-encrypted-template
```

### 2. Install and or Create and Activate a Virtual Environment (Recommended)

Install Python 3.11
```bash
windows: https://www.python.org/
```

```bash
Linux/macOS: sudo apt install -y python3.11 python3.11-venv python3.11-dev
```

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```
or
```bash
pip install flask
```

---

## 🚀 Usage

### 1. Run the Flask Server

```bash
python main.py
```

By default, the app runs at:
👉 `http://127.0.0.1:5421/` 
can be changed in the app.run section at the bottom of main.py

### 2. Directory Structure

```
project/
├── main.py               # Main Flask entry point
├── encrypt.py           # RSA and AES encryption logic
├── templates/           # HTML templates
│   └── index.html
├── static/              # Static files (CSS, JS, etc.)
├── saves/              # files for private access only
│   └── caches/        # unused used to store temp files
│   └── logs/          # store debug stuff here
│   └── private/       # store private keys or secure server only info
│   └── public/        # store read only public stuff can be set to automaticly move to static
│   └── users/         # stores a per folder user directory will fix to sql server as optionaly 
├── requirements.txt     # Python dependencies
└── README.md
```

---

## 🔐 Encryption Details

* **RSA System**

  * 4096-bit public/private key support
  * Used to securely exchange AES session keys

* **AES System**

  * 256-bit GCM encryption
  * Random IV per message
  * Used for actual message content encryption

---

## 🛠 Customization

You can:

* Extend the encryption system in `encrypt.py`
* Add new dynamic routes in `main.py`

---

## 📚 Requirements

* Python 3.8 or newer
* Flask (`pip install flask`)

---

## 📜 License

MIT License — feel free to use and modify.

---

## 🧠 Credits

Created by **Drake Donnison / Allycat @ AllTigWelding**
This project is designed for learning, prototyping, and securely starting web projects with built-in cryptography.
