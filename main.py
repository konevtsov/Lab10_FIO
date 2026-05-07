import re
import logging
import sys
import hashlib
from datetime import datetime
from typing import Tuple

LOG_FILE = "registration_requests.log"
FORBIDDEN_LOGINS = ["admin", "root", "user", "test", "guest", "moderator", "support"]

class PasswordMasker:
    @staticmethod
    def mask(password: str) -> str:
        if not password:
            return ""
        hash_obj = hashlib.sha256(password.encode('utf-8'))
        hash_hex = hash_obj.hexdigest()
        return f"***{hash_hex[:8]}***"

class UserRegistrationValidator:
    def __init__(self):
        self._setup_logging()
        self.masker = PasswordMasker()

    def _setup_logging(self):
        self.logger = logging.getLogger("UserRegistrationValidator")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
        file_handler.setFormatter(formatter)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def _validate_login_format(self, login: str) -> Tuple[bool, str]:
        phone_pattern = r'^\+\d-\d{3}-\d{3}-\d{4}$'
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        string_pattern = r'^[a-zA-Z0-9_]{5,}$'
        
        if re.match(phone_pattern, login):
            return True, ""
        if re.match(email_pattern, login):
            return True, ""
        if re.match(string_pattern, login):
            return True, ""
        return False, "Логин не соответствует ни одному из допустимых форматов (телефон: +x-xxx-xxx-xxxx, email: xxx@xxx.xxx, или строка: минимум 5 символов, только латиница, цифры и _)"

    def _validate_login_not_forbidden(self, login: str) -> Tuple[bool, str]:
        if login.lower() in [f.lower() for f in FORBIDDEN_LOGINS]:
            return False, f"Логин '{login}' запрещен (содержится в списке запрещенных логинов)"
        return True, ""

    def _validate_password_length(self, password: str) -> Tuple[bool, str]:
        if len(password) < 7:
            return False, "Пароль должен содержать минимум 7 символов"
        return True, ""

    def _validate_password_charset(self, password: str) -> Tuple[bool, str]:
        cyrillic_pattern = r'^[а-яА-ЯёЁ0-9!@#$%^&*()_+\-=\[\]{};:"\\|,.<>/?`~]+$'
        if not re.match(cyrillic_pattern, password):
            return False, "Пароль должен содержать только кириллицу, цифры и спецсимволы"
        return True, ""

    def _validate_password_case(self, password: str) -> Tuple[bool, str]:
        has_upper = any('А' <= c <= 'Я' or c == 'Ё' for c in password)
        has_lower = any('а' <= c <= 'я' or c == 'ё' for c in password)
        if not has_upper:
            return False, "Пароль должен содержать минимум одну букву в верхнем регистре"
        if not has_lower:
            return False, "Пароль должен содержать минимум одну букву в нижнем регистре"
        return True, ""

    def _validate_password_digit(self, password: str) -> Tuple[bool, str]:
        if not any(c.isdigit() for c in password):
            return False, "Пароль должен содержать минимум одну цифру"
        return True, ""

    def _validate_password_special(self, password: str) -> Tuple[bool, str]:
        special_chars = r'!@#$%^&*()_+\-=\[\]{};:"\\|,.<>/?`~'
        if not any(c in special_chars for c in password):
            return False, "Пароль должен содержать минимум один спецсимвол"
        return True, ""

    def _validate_password_match(self, password: str, confirm: str) -> Tuple[bool, str]:
        if password != confirm:
            return False, "Пароль и подтверждение пароля не совпадают"
        return True, ""

    def register(self, login: str, password: str, confirm_password: str) -> Tuple[str, str]:
        masked_password = self.masker.mask(password)
        masked_confirm = self.masker.mask(confirm_password)
        
        if not login or login.strip() == "":
            error_msg = "Логин не может быть пустым"
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {error_msg}")
            return "False", error_msg
        
        valid, msg = self._validate_login_format(login)
        if not valid:
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {msg}")
            return "False", msg
        
        valid, msg = self._validate_login_not_forbidden(login)
        if not valid:
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {msg}")
            return "False", msg
        
        if not password:
            error_msg = "Пароль не может быть пустым"
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {error_msg}")
            return "False", error_msg
        
        valid, msg = self._validate_password_length(password)
        if not valid:
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {msg}")
            return "False", msg
        
        valid, msg = self._validate_password_charset(password)
        if not valid:
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {msg}")
            return "False", msg
        
        valid, msg = self._validate_password_case(password)
        if not valid:
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {msg}")
            return "False", msg
        
        valid, msg = self._validate_password_digit(password)
        if not valid:
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {msg}")
            return "False", msg
        
        valid, msg = self._validate_password_special(password)
        if not valid:
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {msg}")
            return "False", msg
        
        valid, msg = self._validate_password_match(password, confirm_password)
        if not valid:
            self.logger.error(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Ошибка: {msg}")
            return "False", msg
        
        self.logger.info(f"Логин: {login} | Пароль: {masked_password} | Подтверждение: {masked_confirm} | Успешная регистрация")
        return "True", ""

def main():
    validator = UserRegistrationValidator()
    print("=== Регистрация пользователя ===")
    print("Форматы логина:")
    print("  - Телефон: +7-123-456-7890")
    print("  - Email: user@example.com")
    print("  - Строка: только латиница, цифры и _, минимум 5 символов")
    print("\nТребования к паролю:")
    print("  - Минимум 7 символов")
    print("  - Только кириллица, цифры и спецсимволы")
    print("  - Минимум 1 буква в верхнем регистре")
    print("  - Минимум 1 буква в нижнем регистре")
    print("  - Минимум 1 цифра")
    print("  - Минимум 1 спецсимвол (!@#$%^&*()_+ и т.д.)")
    print("\n" + "="*50)
    
    login = input("Введите логин: ").strip()
    password = input("Введите пароль: ")
    confirm = input("Подтвердите пароль: ")
    
    result, message = validator.register(login, password, confirm)
    
    print("\n" + "="*50)
    print(f"Результат: {result}")
    if message:
        print(f"Сообщение: {message}")
    else:
        print("Сообщение: (пусто)")
    print("="*50)

if __name__ == "__main__":
    main()