import json
import base64
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, Union
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import os


class SbomSigner:
    """
    Класс для создания и проверки цифровых подписей RSA-SHA256
    для SBOM файлов формата CycloneDX
    """
    
    # Константы алгоритмов
    SIGNATURE_ALGORITHM = "SHA256withRSA"
    HASH_ALGORITHM = "SHA256"
    KEY_ALGORITHM = "RSA"
    
    def __init__(
        self,
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        key_passphrase: Optional[Union[str, bytes]] = None
    ):
        """
        Инициализация подписывателя RSA-SHA256
        
        Args:
            private_key_path: Путь к приватному ключу в PEM формате
            public_key_path: Путь к публичному ключу в PEM формате
            key_passphrase: Пароль для приватного ключа (строка или bytes)
        """
        self.private_key = None
        self.public_key = None
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        
        # Конвертируем пароль в bytes если нужно
        if isinstance(key_passphrase, str):
            self.key_passphrase = key_passphrase.encode('utf-8')
        else:
            self.key_passphrase = key_passphrase
        
        # Загружаем ключи если пути предоставлены
        if private_key_path:
            self.load_private_key(private_key_path)
        
        if public_key_path:
            self.load_public_key(public_key_path)
    
    def load_private_key(self, key_path: str) -> None:
        """
        Загрузка приватного ключа из файла PEM
        
        Args:
            key_path: Путь к файлу с приватным ключом
            
        Raises:
            FileNotFoundError: Если файл не найден
            ValueError: Если ключ невалидный или требуется пароль
        """
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Файл приватного ключа не найден: {key_path}")
        
        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
        
        try:
            # Пробуем загрузить без пароля
            self.private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
        except (TypeError, ValueError):
            # Пробуем с паролем если предоставлен
            if self.key_passphrase:
                try:
                    self.private_key = serialization.load_pem_private_key(
                        key_data,
                        password=self.key_passphrase,
                        backend=default_backend()
                    )
                except Exception as e:
                    raise ValueError(f"Ошибка загрузки приватного ключа с паролем: {e}")
            else:
                raise ValueError(
                    "Для ключа требуется пароль. Укажите key_passphrase в конструкторе "
                    "или используйте метод set_key_passphrase()"
                )
        
        self.private_key_path = key_path
        print(f"✓ Приватный ключ RSA загружен: {key_path}")
        print(f"  Размер ключа: {self.private_key.key_size} бит")
    
    def load_public_key(self, key_path: str) -> None:
        """
        Загрузка публичного ключа из файла PEM
        
        Args:
            key_path: Путь к файлу с публичным ключом
        """
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Файл публичного ключа не найден: {key_path}")
        
        with open(key_path, "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        
        self.public_key_path = key_path
        print(f"✓ Публичный ключ RSA загружен: {key_path}")
    
    def set_key_passphrase(self, passphrase: Union[str, bytes]) -> None:
        """
        Установка пароля для приватного ключа
        
        Args:
            passphrase: Пароль (строка или bytes)
        """
        if isinstance(passphrase, str):
            self.key_passphrase = passphrase.encode('utf-8')
        else:
            self.key_passphrase = passphrase
    
    def generate_key_pair(
        self,
        key_size: int = 2048,
        output_dir: str = "keys",
        key_name: str = "sbom_rsa_key"
    ) -> Tuple[str, str]:
        """
        Генерация новой пары RSA ключей
        
        Args:
            key_size: Размер ключа в битах (2048, 3072, 4096)
            output_dir: Директория для сохранения ключей
            key_name: Базовое имя для файлов ключей
            
        Returns:
            Кортеж (путь_к_приватному_ключу, путь_к_публичному_ключу)
        """
        if key_size not in [2048, 3072, 4096]:
            raise ValueError("Размер ключа должен быть 2048, 3072 или 4096 бит")
        
        print(f"Генерация RSA ключей ({key_size} бит)...")
        
        # Генерация приватного ключа
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Создание директории
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Пути для файлов ключей
        private_key_path = os.path.join(output_dir, f"{key_name}_private.pem")
        public_key_path = os.path.join(output_dir, f"{key_name}_public.pem")
        
        # Сохранение приватного ключа
        encryption_algorithm = serialization.BestAvailableEncryption(
            self.key_passphrase
        ) if self.key_passphrase else serialization.NoEncryption()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        with open(private_key_path, "wb") as f:
            f.write(private_pem)
        
        # Сохранение публичного ключа
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(public_key_path, "wb") as f:
            f.write(public_pem)
        
        # Сохраняем ключи в объекте
        self.private_key = private_key
        self.public_key = public_key
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        
        print(f"✓ RSA ключи сгенерированы и сохранены:")
        print(f"  Приватный ключ: {private_key_path}")
        print(f"  Публичный ключ: {public_key_path}")
        
        return private_key_path, public_key_path
    
    def sign_file(self, file_path: str) -> str:
        """
        Основной метод для подписания файла RSA-SHA256
        
        Args:
            file_path: Путь к файлу для подписи
            
        Returns:
            Путь к подписанному файлу
            
        Raises:
            ValueError: Если приватный ключ не загружен
            FileNotFoundError: Если файл не найден
        """
        if not self.private_key:
            raise ValueError("Приватный ключ не загружен. Используйте load_private_key() или generate_key_pair()")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл не найден: {file_path}")
        
        print(f"\n{'='*60}")
        print(f"ПОДПИСАНИЕ ФАЙЛА: {Path(file_path).name}")
        print(f"{'='*60}")
        
        # Определяем тип файла и выбираем стратегию подписи
        file_ext = Path(file_path).suffix.lower()
        
        if file_ext == '.json':
            return self._sign_json_file(file_path)
        else:
            return self._sign_binary_file(file_path)
    
    def _sign_json_file(self, file_path: str) -> str:
        """
        Подписание JSON файла (SBOM в формате CycloneDX)
        
        Args:
            file_path: Путь к JSON файлу
            
        Returns:
            Путь к подписанному файлу
        """
        try:
            # Чтение и проверка JSON
            with open(file_path, 'r', encoding='utf-8') as f:
                sbom = json.load(f)
            
            # Проверка формата CycloneDX
            bom_format = sbom.get('bomFormat')
            if bom_format and bom_format != 'CycloneDX':
                print(f"⚠ Внимание: Файл не в формате CycloneDX (bomFormat: {bom_format})")
            
            # Подготовка SBOM для подписи
            sbom_for_signing = self._prepare_sbom_for_signing(sbom)
            
            # Каноническое представление (важно для детерминированной подписи)
            canonical_json = json.dumps(
                sbom_for_signing,
                sort_keys=True,
                separators=(',', ':'),
                ensure_ascii=False
            )
            
            print(f"Каноническое представление создано ({len(canonical_json)} символов)")
            
            # Создание подписи RSA-SHA256
            signature_bytes = self._create_rsa_sha256_signature(canonical_json)
            
            # Добавление подписи в SBOM
            signed_sbom = self._embed_signature_in_sbom(sbom, signature_bytes, canonical_json)
            
            # Сохранение подписанного SBOM
            signed_file_path = self._save_signed_file(file_path, signed_sbom)
            
            # Создание отдельного файла подписи
            self._create_signature_file(file_path, signature_bytes, canonical_json)
            
            return signed_file_path
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Файл не является валидным JSON: {e}")
        except Exception as e:
            raise RuntimeError(f"Ошибка при подписании JSON файла: {e}")
    
    def _sign_binary_file(self, file_path: str) -> str:
        """
        Подписание бинарного файла
        
        Args:
            file_path: Путь к бинарному файлу
            
        Returns:
            Путь к файлу подписи
        """
        print(f"Подписание бинарного файла...")
        
        # Чтение файла
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Вычисление SHA256 хеша
        file_hash = hashlib.sha256(file_data).digest()
        print(f"SHA256 хеш файла: {file_hash.hex()}")
        
        # Создание подписи RSA-SHA256
        signature_bytes = self._create_rsa_sha256_signature(file_data)
        
        # Сохранение подписи в отдельный файл
        signature_file_path = self._create_signature_file(file_path, signature_bytes, file_data)
        
        return signature_file_path
    
    def _prepare_sbom_for_signing(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """
        Подготовка SBOM для подписи (удаление существующих подписей)
        
        Args:
            sbom: Словарь SBOM
            
        Returns:
            Очищенный словарь SBOM
        """
        import copy
        sbom_copy = copy.deepcopy(sbom)
        
        # Удаляем существующие подписи
        if 'metadata' in sbom_copy:
            if 'signature' in sbom_copy['metadata']:
                del sbom_copy['metadata']['signature']
            if 'signatures' in sbom_copy['metadata']:
                del sbom_copy['metadata']['signatures']
        
        # Удаляем подпись на верхнем уровне если есть
        if 'signature' in sbom_copy:
            del sbom_copy['signature']
        if 'signatures' in sbom_copy:
            del sbom_copy['signatures']
        
        return sbom_copy
    
    def _create_rsa_sha256_signature(self, data: Union[str, bytes]) -> bytes:
        """
        Создание подписи RSA-SHA256 для данных
        
        Args:
            data: Данные для подписи (строка или bytes)
            
        Returns:
            Подпись в виде bytes
        """
        # Конвертируем строку в bytes если нужно
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        print(f"Создание RSA-SHA256 подписи...")
        
        # Создание подписи с использованием PKCS1v15 padding
        signature = self.private_key.sign(
            data_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        print(f"✓ Подпись создана ({len(signature)} байт)")
        print(f"  Алгоритм: {self.SIGNATURE_ALGORITHM}")
        
        return signature
    
    def _embed_signature_in_sbom(
        self,
        original_sbom: Dict[str, Any],
        signature_bytes: bytes,
        signed_data: Union[str, bytes]
    ) -> Dict[str, Any]:
        """
        Встраивание подписи в структуру SBOM
        
        Args:
            original_sbom: Исходный SBOM
            signature_bytes: Байты подписи
            signed_data: Данные которые были подписаны
            
        Returns:
            SBOM с встроенной подписью
        """
        import copy
        signed_sbom = copy.deepcopy(original_sbom)
        
        # Вычисление SHA256 от подписанных данных
        if isinstance(signed_data, str):
            data_hash = hashlib.sha256(signed_data.encode('utf-8')).digest()
        else:
            data_hash = hashlib.sha256(signed_data).digest()
        
        # Создаем объект подписи
        signature_object = {
            "algorithm": self.SIGNATURE_ALGORITHM,
            "value": base64.b64encode(signature_bytes).decode('utf-8'),
            "hash": {
                "algorithm": self.HASH_ALGORITHM,
                "value": data_hash.hex()
            },
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "key_info": {
                "algorithm": self.KEY_ALGORITHM,
                "size": self.private_key.key_size,
                "fingerprint": self._get_public_key_fingerprint()
            }
        }
        
        # Добавляем подпись в metadata
        if 'metadata' not in signed_sbom:
            signed_sbom['metadata'] = {}
        
        signed_sbom['metadata']['signature'] = signature_object
        
        # Добавляем аннотацию
        if 'annotations' not in signed_sbom['metadata']:
            signed_sbom['metadata']['annotations'] = []
        
        signed_sbom['metadata']['annotations'].append({
            "timestamp": signature_object['timestamp'],
            "subjects": [{"bom-ref": "SIGNATURE"}],
            "annotation": "SBOM подписан цифровой подписью RSA-SHA256",
            "annotationType": "DIGITAL_SIGNATURE"
        })
        
        return signed_sbom
    
    def _get_public_key_fingerprint(self) -> str:
        """
        Получение отпечатка публичного ключа
        
        Returns:
            SHA256 отпечаток ключа в hex
        """
        if not self.public_key:
            # Если нет публичного ключа, используем приватный
            if not self.private_key:
                return "unknown"
            
            public_key = self.private_key.public_key()
        else:
            public_key = self.public_key
        
        # Сериализация публичного ключа
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Вычисление SHA256 отпечатка
        fingerprint = hashlib.sha256(public_bytes).hexdigest()
        
        # Форматирование как стандартный fingerprint (первые 16 байт)
        formatted_fp = ':'.join([fingerprint[i:i+2] for i in range(0, 32, 2)])
        
        return formatted_fp
    
    def _save_signed_file(self, original_path: str, signed_data: Dict[str, Any]) -> str:
        """
        Сохранение подписанного файла
        
        Args:
            original_path: Путь к оригинальному файлу
            signed_data: Подписанные данные
            
        Returns:
            Путь к сохраненному файлу
        """
        original_path_obj = Path(original_path)
        
        # Создаем имя для подписанного файла
        signed_path = original_path_obj.with_name(
            f"{original_path_obj.stem}_signed_rsa.json"
        )
        
        # Сохраняем с красивым форматированием
        with open(signed_path, 'w', encoding='utf-8') as f:
            json.dump(signed_data, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Подписанный SBOM сохранен: {signed_path}")
        print(f"  Размер файла: {signed_path.stat().st_size} байт")
        
        return str(signed_path)
    
    def _create_signature_file(
        self,
        original_path: str,
        signature_bytes: bytes,
        signed_data: Union[str, bytes]
    ) -> str:
        """
        Создание отдельного файла подписи
        
        Args:
            original_path: Путь к оригинальному файлу
            signature_bytes: Байты подписи
            signed_data: Данные которые были подписаны
            
        Returns:
            Путь к файлу подписи
        """
        original_path_obj = Path(original_path)
        
        # Вычисление хеша от подписанных данных
        if isinstance(signed_data, str):
            data_hash = hashlib.sha256(signed_data.encode('utf-8')).digest()
        else:
            data_hash = hashlib.sha256(signed_data).digest()
        
        # Создаем имя для файла подписи
        signature_path = original_path_obj.with_suffix('.rsa.sig')
        
        # Сохраняем информацию о подписи
        signature_info = {
            "original_file": original_path_obj.name,
            "signature_algorithm": self.SIGNATURE_ALGORITHM,
            "signature": base64.b64encode(signature_bytes).decode('utf-8'),
            "hash_algorithm": self.HASH_ALGORITHM,
            "hash_value": data_hash.hex(),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "key_fingerprint": self._get_public_key_fingerprint(),
            "key_size": self.private_key.key_size if self.private_key else None
        }
        
        with open(signature_path, 'w') as f:
            json.dump(signature_info, f, indent=2)
        
        print(f"✓ Файл подписи сохранен: {signature_path}")
        
        return str(signature_path)
    
    def verify_signature(self, file_path: str, signature_file: Optional[str] = None) -> bool:
        """
        Проверка подписи файла
        
        Args:
            file_path: Путь к файлу для проверки
            signature_file: Путь к файлу подписи (опционально)
            
        Returns:
            True если подпись валидна, False в противном случае
        """
        if not self.public_key:
            raise ValueError("Публичный ключ не загружен. Используйте load_public_key()")
        
        print(f"\n{'='*60}")
        print(f"ПРОВЕРКА ПОДПИСИ: {Path(file_path).name}")
        print(f"{'='*60}")
        
        # Определяем тип проверки
        if signature_file:
            return self._verify_external_signature(file_path, signature_file)
        else:
            return self._verify_embedded_signature(file_path)
    
    def _verify_external_signature(self, file_path: str, signature_file: str) -> bool:
        """
        Проверка внешней подписи (отдельный файл)
        
        Args:
            file_path: Путь к файлу
            signature_file: Путь к файлу подписи
            
        Returns:
            True если подпись валидна
        """
        if not os.path.exists(signature_file):
            print(f"✗ Файл подписи не найден: {signature_file}")
            return False
        
        # Чтение файла подписи
        with open(signature_file, 'r') as f:
            signature_info = json.load(f)
        
        signature_b64 = signature_info.get('signature')
        expected_hash = signature_info.get('hash_value')
        
        if not signature_b64:
            print("✗ Не найдена подпись в файле подписи")
            return False
        
        # Декодирование подписи
        signature_bytes = base64.b64decode(signature_b64)
        
        # Чтение файла
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Проверка хеша если есть
        if expected_hash:
            actual_hash = hashlib.sha256(file_data).hexdigest()
            if actual_hash != expected_hash:
                print(f"✗ Хеши не совпадают:")
                print(f"  Ожидался: {expected_hash}")
                print(f"  Получен:  {actual_hash}")
                return False
            else:
                print(f"✓ Хеш файла подтвержден")
        
        # Проверка подписи
        try:
            self.public_key.verify(
                signature_bytes,
                file_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print(f"✓ RSA-SHA256 подпись верифицирована успешно")
            return True
            
        except InvalidSignature:
            print(f"✗ Невалидная RSA-SHA256 подпись")
            return False
        except Exception as e:
            print(f"✗ Ошибка при верификации: {e}")
            return False
    
    def _verify_embedded_signature(self, file_path: str) -> bool:
        """
        Проверка встроенной подписи (внутри SBOM JSON)
        
        Args:
            file_path: Путь к SBOM файлу
            
        Returns:
            True если подпись валидна
        """
        try:
            # Чтение SBOM
            with open(file_path, 'r', encoding='utf-8') as f:
                sbom = json.load(f)
            
            # Поиск подписи в metadata
            signature_data = None
            if 'metadata' in sbom and 'signature' in sbom['metadata']:
                signature_data = sbom['metadata']['signature']
            
            if not signature_data:
                print("✗ Не найдена встроенная подпись в SBOM")
                return False
            
            signature_b64 = signature_data.get('value')
            if not signature_b64:
                print("✗ Не найдено значение подписи")
                return False
            
            # Декодирование подписи
            signature_bytes = base64.b64decode(signature_b64)
            
            # Подготовка SBOM для верификации (удаляем подпись)
            sbom_for_verification = self._prepare_sbom_for_signing(sbom)
            
            # Каноническое представление
            canonical_json = json.dumps(
                sbom_for_verification,
                sort_keys=True,
                separators=(',', ':'),
                ensure_ascii=False
            )
            
            # Проверка подписи
            try:
                self.public_key.verify(
                    signature_bytes,
                    canonical_json.encode('utf-8'),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                
                print(f"✓ RSA-SHA256 подпись верифицирована успешно")
                
                # Дополнительная проверка хеша если есть
                if 'hash' in signature_data and 'value' in signature_data['hash']:
                    expected_hash = signature_data['hash']['value']
                    actual_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
                    
                    if actual_hash == expected_hash:
                        print(f"✓ Хеш содержимого подтвержден")
                    else:
                        print(f"⚠ Хеш содержимого не совпадает")
                
                # Вывод информации о подписи
                self._print_signature_info(signature_data)
                
                return True
                
            except InvalidSignature:
                print(f"✗ Невалидная RSA-SHA256 подпись")
                return False
                
        except json.JSONDecodeError:
            print("✗ Файл не является валидным JSON")
            return False
        except Exception as e:
            print(f"✗ Ошибка при верификации: {e}")
            return False
    
    def _print_signature_info(self, signature_data: Dict[str, Any]) -> None:
        """Вывод информации о подписи"""
        print(f"\nИнформация о подписи:")
        print(f"  Алгоритм: {signature_data.get('algorithm', 'неизвестно')}")
        
        timestamp = signature_data.get('timestamp')
        if timestamp:
            print(f"  Время подписания: {timestamp}")
        
        if 'key_info' in signature_data:
            key_info = signature_data['key_info']
            print(f"  Алгоритм ключа: {key_info.get('algorithm')}")
            print(f"  Размер ключа: {key_info.get('size')} бит")
            
            fingerprint = key_info.get('fingerprint')
            if fingerprint:
                print(f"  Отпечаток ключа: {fingerprint}")
    
    def export_public_key_pem(self, output_path: Optional[str] = None) -> str:
        """
        Экспорт публичного ключа в PEM формате
        
        Args:
            output_path: Путь для сохранения (опционально)
            
        Returns:
            Путь к сохраненному файлу
        """
        if not self.public_key:
            if self.private_key:
                self.public_key = self.private_key.public_key()
            else:
                raise ValueError("Нет публичного ключа для экспорта")
        
        if not output_path:
            if self.public_key_path:
                output_path = self.public_key_path
            else:
                output_path = "public_key.pem"
        
        # Генерация PEM
        pem_data = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Сохранение
        with open(output_path, 'wb') as f:
            f.write(pem_data)
        
        print(f"✓ Публичный ключ экспортирован: {output_path}")
        
        return output_path