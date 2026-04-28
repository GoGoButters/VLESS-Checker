# VPN Checker

Автоматизированный агрегатор, тестер и дистрибьютор прокси-серверов с **распределённой архитектурой** (менеджер + воркеры).  
Проект поддерживает множество протоколов (VLESS, VMess, Trojan, Shadowsocks, Hysteria2) благодаря использованию ядра [sing-box](https://sing-box.sagernet.org/).

## Архитектура

Система разделена на два компонента:

### 🖥️ Менеджер (Master Panel)
Веб-панель управления, которая **не выполняет тестирование прокси**. Её задачи:
- Скачивание и парсинг подписок с прокси
- Хранение и дедупликация прокси-ссылок
- Раздача прокси-ссылок воркерам через API
- Агрегация результатов тестирования от воркеров
- Раздача лучших прокси через webhook (для VPN-клиентов)
- Управление настройками, подписками и тестовыми URL

### ⚙️ Воркер (Worker Node)
Выполняет всю работу по тестированию прокси. Поддерживает два режима запуска:

**Docker-режим:**
- Headless Docker-контейнер с автоматической установкой sing-box
- Быстрое развёртывание

**Standalone-режим:**
- Запуск без Docker (LXC-контейнеры, виртуальные машины, bare metal)
- Требует Python 3.11+ и установки sing-box вручную (скрипт `setup.sh`)

Функции воркера:
- Получает список прокси от менеджера
- Тестирует каждый прокси (TCP ping + тестовые URL через sing-box)
- Опционально измеряет скорость (download/upload)
- Отправляет результаты обратно менеджеру

## Особенности
- **Распределённая архитектура**: Менеджер не тестирует — все тесты выполняются воркерами из разных регионов.
- **Мультипротокольность**: VLESS, VMess, Trojan, Shadowsocks, Hysteria2.
- **Глобальный консенсус**: Прокси ранжируются по числу воркеров, которые их подтвердили.
- **Авто-обновление**: Планировщик периодически скачивает подписки, воркеры автоматически подхватывают новые прокси.
- **Стойкость к DPI**: Встроены проверки для обхода ТСПУ и геоблокировок (Instagram, YouTube, ChatGPT, RuTracker и др.).
- **Zero-Downtime Webhook**: Простая раздача лучших прокси в VPN-приложения.
- **Web-интерфейс**: FastAPI + Jinja2 + Tailwind CSS с Dark Mode / Glassmorphism UI.

## Требования

### Менеджер (VPS)
- **ОС**: Любой Linux (Ubuntu, Debian, Rocky и др.)
- **Docker и Docker Compose**
- Минимально: 1 vCPU, 256MB RAM, 5GB SSD
- **Не требуется** sing-box — менеджер не тестирует прокси

### Воркер (VPS)
- **ОС**: Любой Linux
- **Два режима:**
  - **Docker**: Docker и Docker Compose (рекомендуется)
  - **Standalone**: Python 3.11+, sing-box, без Docker
- Минимально: 1 vCPU, 512MB RAM, 5GB SSD

## Развертывание менеджера

1. **Клонируйте репозиторий**:
```bash
git clone https://github.com/GoGoButters/VLESS-Checker.git
cd VLESS-Checker
```

2. **Сборка и запуск контейнера**:
```bash
docker compose up -d --build
```

3. **Доступ к панели управления**:
```
http://<ВАШ_IP_АДРЕС>:8000
```
- **Пароль по умолчанию**: `admin`
- *(Обязательно смените в разделе **Settings** → Security)*

## Развертывание воркера

Выберите способ развертывания:

---

### Docker-режим (рекомендуется)

На отдельном сервере:

1. **Клонируйте репозиторий**:
```bash
git clone https://github.com/GoGoButters/VLESS-Checker.git
cd VLESS-Checker/node
```

2. **Настройте `docker-compose.yml`**:
```yaml
environment:
  - MASTER_URL=http://<IP_МЕНЕДЖЕРА>:8000
  - NODE_TOKEN=<токен из Settings менеджера>
  - NODE_NAME=my-worker-1
  - NODE_REGION=Russia
```

3. **Запустите воркер**:
```bash
docker compose up -d --build
```

---

### Standalone-режим (без Docker)

Подходит для LXC-контейнеров, виртуальных машин или bare metal.

1. **Клонируйте репозиторий**:
```bash
git clone https://github.com/GoGoButters/VLESS-Checker.git
cd VLESS-Checker/node
```

2. **Запустите установку** (установит Python, sing-box, зависимости):
```bash
chmod +x setup.sh
./setup.sh
```

3. **Скопируйте и отредактируйте конфигурацию**:
```bash
cp .env.example .env
nano .env
```
Отредактируйте `.env`:
- `MASTER_URL` — адрес менеджера
- `NODE_TOKEN` — токен из **Settings → Node Management** в панели
- `NODE_NAME` — имя воркера
- `NODE_REGION` — регион

4. **Запустите воркер**:
```bash
./run.sh
```

Воркер автоматически зарегистрируется на менеджере и начнёт тестирование прокси.

## Настройка системы

В панели управления (**Settings**):
- **Worker Test Parameters** — Ping-порог, concurrency, таймауты (эти настройки передаются воркерам)
- **Auto-Fetch Scheduler** — Интервал автоматического скачивания подписок (минуты, 0 = отключено)
- **Webhook** — Секретный путь и лимит прокси для раздачи
- **Node Management** — API-токен для воркеров, лимит прокси на воркер
- **Global Consensus Sub** — Лимит для глобальной подписки (ранжирование по кросс-нодовому консенсусу)
- **Security** — Смена пароля администратора

## Webhook-эндпоинты

| Эндпоинт | Описание |
|---|---|
| `/{secret_path}` | Лучшие прокси по скорости (агрегация всех воркеров) |
| `/{secret_path}/global` | Глобальный консенсус — ранжирование по числу подтвердивших нод |
| `/{secret_path}/node/{id}` | Прокси конкретного воркера |

## Обновление

```bash
cd VLESS-Checker
git pull
docker compose build --no-cache
docker compose up -d
```

База данных сохраняется в volume `vpn_data` и не стирается при обновлении.

## Технологии
- FastAPI (Python 3.11+)
- SQLModel / SQLite
- Jinja2, Tailwind CSS (Dark Mode / Glassmorphism)
- [sing-box](https://github.com/SagerNet/sing-box) (только в воркерах)
