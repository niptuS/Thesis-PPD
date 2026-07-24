"""
Entrada: None
Salida: Translation module
Descripción: Loads translations from design/language/*.json files and provides
             a t() helper for retrieving localized strings. Logs are always
             emitted in English regardless of the selected UI language.
"""
from __future__ import annotations
import json
from pathlib import Path

LANG_DIR = Path(__file__).parent.parent / "design" / "language"
LANGUAGES = {"en": "English", "es": "Español"}

_current_lang = "en"
_translations: dict[str, dict] = {}


"""
Entrada: lang (str)
Salida: dict — nested translation dictionary
Descripción: Loads a language JSON file.
"""
def _load_language(lang: str) -> dict:
    path = LANG_DIR / f"{lang}.json"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


"""
Entrada: None
Salida: None
Descripción: Loads all language files on first access.
"""
def _ensure_loaded():
    if not _translations:
        for lang in LANGUAGES:
            _translations[lang] = _load_language(lang)


"""
Entrada: lang (str)
Salida: None
Descripción: Sets the active UI language.
"""
def set_language(lang: str) -> None:
    global _current_lang
    if lang in LANGUAGES:
        _current_lang = lang


"""
Entrada: None
Salida: str
Descripción: Returns the current language code.
"""
def get_language() -> str:
    return _current_lang


"""
Entrada: section (str), key (str), *args (positional placeholders)
Salida: str — translated string
Descripción: Gets a translated string by section.key path. Falls back to English.
             If positional args are provided, they are interpolated into {N}
             placeholders in the translated string.
"""
def t(section: str, key: str, *args) -> str:
    _ensure_loaded()
    lang_data = _translations.get(_current_lang, {})
    en_data = _translations.get("en", {})
    result = lang_data.get(section, {}).get(key)
    if result is None:
        result = en_data.get(section, {}).get(key, key)
    if args:
        try:
            result = result.format(*args)
        except (IndexError, KeyError, ValueError):
            pass
    return result


"""
Entrada: section (str), key (str), *args (positional placeholders)
Salida: str — English translated string
Descripción: Gets the English translation regardless of the current UI language.
             Used for log messages so logs are always in English.
"""
def t_en(section: str, key: str, *args) -> str:
    _ensure_loaded()
    en_data = _translations.get("en", {})
    result = en_data.get(section, {}).get(key, key)
    if args:
        try:
            result = result.format(*args)
        except (IndexError, KeyError, ValueError):
            pass
    return result
