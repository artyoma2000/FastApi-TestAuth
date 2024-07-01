# 🌟 Пример аутентификации FastAPI с использованием JWT

[![FastAPI](https://img.shields.io/badge/FastAPI-0.95.2-brightgreen)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue)](https://www.python.org/downloads/release/python-380/)
[![License](https://img.shields.io/badge/License-MIT-yellowgreen)](LICENSE)

> 🛡️ Пример приложения на FastAPI с использованием аутентификации JWT (JSON Web Token).

## 🎯 Возможности

- **JWT Аутентификация**: Безопасная аутентификация пользователей и защита API конечных точек.
- **FastAPI**: Построено на современном и быстром фреймворке Python.
- **Безопасность на основе токенов**: Обеспечивает безопасный доступ с истекающими токенами.

## 🚀 Быстрый старт

### Предварительные требования

- Python 3.8+
- Менеджер пакетов `pip`

### Установка

1. **Клонируйте репозиторий**:
   ```bash
   git clone https://github.com/yourusername/fastapi-jwt-auth.git
   cd fastapi-jwt-auth
   ```

2. **Создайте и активируйте виртуальное окружение**:
   ```bash
   python -m venv env
   source env/bin/activate  # Для Windows используйте `env\Scripts\activate`
   ```

3. **Установите зависимости**:
   ```bash
   pip install -r requirements.txt
   ```

### Запуск приложения

1. **Запустите сервер FastAPI**:
   ```bash
   uvicorn main:app --reload
   ```

2. **Получите доступ к документации API**:
   - Перейдите по адресу [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) для интерактивного Swagger UI.
   - Или откройте [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc) для ReDoc.

## 🛠️ Использование

### Получение JWT Токена

1. **Отправьте POST запрос на `/login`**:
   ```json
   POST /login
   Content-Type: application/json

   {
     "username": "john_doe",
     "password": "securepassword123"
   }
   ```

2. **Ответ**:
   ```json
   {
     "access_token": "<ваш_jwt_токен>",
     "token_type": "bearer"
   }
   ```

### Доступ к защищенному ресурсу

1. **Отправьте GET запрос на `/protected_resource` с заголовком Authorization**:
   ```http
   GET /protected_resource
   Authorization: Bearer <ваш_jwt_токен>
   ```

2. **Ответ**:
   ```json
   {
     "message": "Привет john_doe, вы получили доступ к защищенному ресурсу."
   }
   ```

## 📄 API Конечные точки

- **`POST /login`**: Аутентифицирует пользователя и возвращает JWT.
- **`GET /protected_resource`**: Доступ к защищенному контенту с валидным JWT.

## 🧩 Дальнейшая кастомизация

- **Настройка срока действия токена**: Измените срок действия токена в функции `create_access_token`.
- **Безопасное управление ключами**: Храните `SECRET_KEY` безопасно (например, в переменных окружения).
- **Интеграция с базой данных**: Замените функцию `authenticate_user` на реальные запросы к базе данных.

## 🤝 Участие

Мы приветствуем ваши предложения и улучшения! Пожалуйста, открывайте issue или отправляйте pull request для улучшений.

## 📜 Лицензия

Этот проект лицензирован по лицензии MIT - подробности см. в файле [LICENSE](LICENSE).

## 🌐 Ссылки

- [Документация FastAPI](https://fastapi.tiangolo.com/)
- [Документация PyJWT](https://pyjwt.readthedocs.io/en/stable/)

