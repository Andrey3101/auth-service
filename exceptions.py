class AuthError(Exception):
    """Ошибка аутентификации или авторизации."""
    pass

class ValidationError(Exception):
    """Ошибка валидации данных."""
    pass
