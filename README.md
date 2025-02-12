# Стенд для курса "Основы QA"

Проект содержит исходный курс стенда с формой логина для курса "Основы QA".

⚠️ **Если вы ученик, переходите на [развернутый стенд](http://qa-stand-login.inzhenerka.tech/) и занимайтесь.
Исходный код вам не нужен** ⚠️

## Запуск

Установка требований (Python 3.11):

```bash
pip install -e .
```

Запуск приложения:

```bash
python3 app_dev.py
```

Запуск контейнера:

```bash
docker-compose build
docker-compose up -d
```

## Требования и описание

## 1. Стенд “Страница с логином”

Состоит из двух страниц: 

1) сам логин 

2) страница с приветствием и данными из базы данных (указано внизу)

| Поле          | Параметр                                                             |
|---------------|----------------------------------------------------------------------|
| Поле “Логин”  | Есть элемент с идентификатором “username”                            |
| Поле “Пароль” | Элемент есть, но ID не указан (труднее работает с автоматизацией)    |
| Поле “Вход”   | Поле “входа” в систему. Есть название класса “loginClass”, но нет ID |

**Вход в систему:**

| Логин / Пароль                | Ожидание                                                             |
|-------------------------------|----------------------------------------------------------------------|
| admin / admin123              | Вход в систему, страница с приветствием “Привет, (имя пользователя)” |
| (пустые поля логина и пароля) | Вход в систему, страница с приветствием “Привет, (имя пользователя)” |
| user / user123                | Вход в систему, страница с приветствием “Привет, (имя пользователя)” |

После входа в систему появляется:

- Имя пользователя (user123)
- Имя и фамилия
- Должность (как в базе данных, смотри ниже во втором кейсе)
- Возраст
- Пол
- Админ? (true/false)
- Описание
- Кнопка “Выход” (возвращает обратную на страницу логина)

На второй странице можно кроме приветствия также разместить рекламу курса, ссылки на другие курсы и так далее.

## 2. Стенд API тестирование

К системе выше с помощью методов POST, GET и UPDATE можно добавлять пользователей, изменять и получать их. 

Доступ должен быть с API ключом `API_KEY123`, без него данные невозможно считать или изменить.

| Поле в базе данных    | Что значит         |
|-----------------------|--------------------|
| username (уникальное) | Имя                |
| password              | Пароль             |
| jobtitle              | Должность          |
| age                   | Возраст            |
| admin                 | Админ (true/false) |
| description           | Описание           |

## Развертывание на EC2 (AL2023)

Установка Docker:

```bash
sudo dnf update -y
sudo dnf install docker -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
newgrp docker
```

Установка Docker Compose:

```bash
mkdir -p $HOME/.docker/cli-plugins
touch $HOME/.docker/config.json
sudo curl -sL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m) \
  -o /usr/local/bin/docker-compose
# Make executable
sudo chown root:root /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

Установка Git:

```bash
sudo dnf install git -y
```

Клонирование репозитория:

```bash
git clone https://github.com/Inzhenerka/qa_stand_login.git
```

Первый запуск certbot для получения SSL-сертификата:

```bash
cd qa_stand_login
docker-compose run --rm certbot certonly --webroot --webroot-path=/var/www/certbot --email info@inzhenerka.tech --agree-tos --no-eff-email --staging --domains qa-stand-login.inzhenerka.tech
```
