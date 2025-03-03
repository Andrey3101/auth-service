# Auth-Service

Сервис аутентификации и авторизации пользователей.

## Текущая схема
- **Технологии**: Python 3.11, FastAPI, SQLAlchemy, Redis, RabbitMQ
- **Функционал**:
  - Регистрация пользователей и компаний (`/register`)
  - Аутентификация (`/login`) с выдачей JWT и CSRF-токенов
  - Выход из системы (`/logout`) с занесением токена в черный список
  - Обновление токенов (`/refresh`)
  - Управление профилем (`/profile`): получение и обновление (только для Admin)
  - Генерация отчетов для SuperAdmin (`/superadmin/stats`)
  - Ротация JWT_SECRET каждые 24 часа с поддержкой старых ключей
- **Зависимости**:
  - PostgreSQL (`auth_db`) для хранения пользователей и компаний
  - Redis для кэширования профилей и черного списка токенов
  - RabbitMQ для отправки уведомлений
- **Структура БД**:
  - `companies`: `company_id (UUID PK), name (String), inn (String UNIQUE), created_at (DateTime)`
  - `users`: `user_id (UUID PK), email (String UNIQUE), password_hash (String), company_id (UUID FK), role (String: super_admin/admin/user), created_at (DateTime)`

## Запуск
1. Установите зависимости: `pip install -r requirements.txt`
2. Настройте переменные окружения в `docker-compose.yml`
3. Запустите: `docker-compose up`

## Предложенные доработки
1. **Многофакторная аутентификация (MFA)**:
   - Добавить поддержку OTP (через email или Telegram) для повышения безопасности.
   - Реализация: добавить поле `otp_secret` в `users` и эндпоинт `/mfa/verify`.
2. **Аудит действий**:
   - Создать таблицу `auth.audit_log` для логирования входов, изменений профиля и т.д.
   - Пример: `audit_id (UUID PK), user_id (UUID), action (String), timestamp (DateTime)`.
3. **Роли с гранулярными правами**:
   - Заменить строковые роли на таблицу `roles` с правами (e.g., `can_create_users`, `can_view_reports`).
4. **Ограничение попыток входа**:
   - Ввести лимит на неудачные попытки входа с временной блокировкой через Redis.