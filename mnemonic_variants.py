"""
Перебор вариаций мнемоника котёнка как BIP39 passphrase.

Мнемоник котёнка (24 слова):
blossom educate state course sick fresh color divide number soap please pull
glide weather join grit depart dynamic tenant leopard alter piano slight room

Запуск:
  python3 mnemonic_variants.py          # перестановки до 4 слов (~267K)
  python3 mnemonic_variants.py --deep   # + перестановки 5 слов (~5.4M)
"""
import sys
import hashlib
from itertools import permutations

from bip_utils import Bip39SeedGenerator, Bip84, Bip84Coins, Bip44Changes
from concurrent.futures import ProcessPoolExecutor
import os

BTC_ADDRESS = "bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r"

KITTEN_MNEMONIC = (
    "blossom educate state course sick fresh color divide number soap please pull "
    "glide weather join grit depart dynamic tenant leopard alter piano slight room"
)

WORDS = KITTEN_MNEMONIC.split()  # 24 слова


# ---------------------------------------------------------------------------
# Проверка одного passphrase
# ---------------------------------------------------------------------------

def get_address(passphrase: str) -> str:
    seed = Bip39SeedGenerator(KITTEN_MNEMONIC).Generate(passphrase)
    bip84 = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
    wallet = bip84.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    return wallet.PublicKey().ToAddress()


def check_batch(phrases: list[str]) -> str | None:
    """Проверяет пачку фраз, возвращает найденный passphrase или None."""
    for phrase in phrases:
        if get_address(phrase).lower() == BTC_ADDRESS.lower():
            return phrase
    return None


# ---------------------------------------------------------------------------
# Генераторы вариантов
# ---------------------------------------------------------------------------

def basic_variants() -> list[str]:
    """Простые варианты без перестановок."""
    variants = []

    # Пустой пароль
    variants.append("")

    # Полный мнемоник с разными разделителями
    for sep in [" ", "", ",", "-", "_", ".", "|"]:
        s = sep.join(WORDS)
        variants.append(s)
        variants.append(s.upper())
        variants.append(s.capitalize())

    # Обратный порядок
    rev = list(reversed(WORDS))
    for sep in [" ", "", "-"]:
        variants.append(sep.join(rev))

    # Каждое слово отдельно (+ upper + capitalize)
    for word in WORDS:
        variants.append(word)
        variants.append(word.upper())
        variants.append(word.capitalize())

    # Первые N слов
    for n in range(1, len(WORDS) + 1):
        variants.append(" ".join(WORDS[:n]))
        variants.append(" ".join(WORDS[:n]).upper())

    # Последние N слов
    for n in range(1, len(WORDS) + 1):
        variants.append(" ".join(WORDS[-n:]))

    # Каждые через одно
    variants.append(" ".join(WORDS[::2]))
    variants.append(" ".join(WORDS[1::2]))
    variants.append(" ".join(reversed(WORDS[::2])))

    # SHA256 от мнемоника (hex)
    h = hashlib.sha256(KITTEN_MNEMONIC.encode()).hexdigest()
    variants.append(h)
    variants.append(h[:32])
    variants.append(h[:16])

    return list(dict.fromkeys(variants))  # убираем дубли, сохраняя порядок


def perm_variants(max_len: int = 4, sep: str = " ") -> list[str]:
    """
    Все перестановки от 2 до max_len слов из мнемоника.
    max_len=2: P(24,2) =      552
    max_len=3: P(24,3) =   12,144
    max_len=4: P(24,4) =  255,024
    max_len=5: P(24,5) = 5,100,480
    """
    result = []
    for r in range(2, max_len + 1):
        for perm in permutations(WORDS, r):
            result.append(sep.join(perm))
    return result


# ---------------------------------------------------------------------------
# Вывод прогресса и поиск
# ---------------------------------------------------------------------------

def search(variants: list[str], label: str, workers: int):
    total = len(variants)
    print(f"\n{label}: {total:,} вариантов")

    batch_size = max(1, total // (workers * 20))
    batches = [variants[i:i + batch_size] for i in range(0, total, batch_size)]

    found = None
    completed = 0

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_batch, b): b for b in batches}
        try:
            for future in futures:
                result = future.result()
                completed += len(futures[future])
                pct = completed / total * 100
                print(f"\r  [{pct:5.1f}%] {completed:,}/{total:,}", end="", flush=True)
                if result is not None:
                    found = result
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
        except KeyboardInterrupt:
            print("\nОстановлено пользователем.")
            executor.shutdown(wait=False, cancel_futures=True)

    print()
    return found


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def main():
    deep = "--deep" in sys.argv
    workers = max(1, os.cpu_count() - 1)
    max_perm_len = 5 if deep else 4

    print(f"Целевой адрес : {BTC_ADDRESS}")
    print(f"Слов в мнемонике: {len(WORDS)}")
    print(f"Режим         : {'--deep (до 5 слов)' if deep else 'обычный (до 4 слов)'}")
    print(f"Процессов     : {workers}")

    # Шаг 1: базовые варианты (быстро)
    basics = basic_variants()
    found = search(basics, "Базовые варианты (windows, reverse, регистр)", workers)

    if found:
        print(f"\n✓ ПАРОЛЬ НАЙДЕН: {repr(found)}")
        return

    # Шаг 2: перестановки (основной объём)
    perms = perm_variants(max_len=max_perm_len, sep=" ")
    found = search(perms, f"Перестановки слов (r=2..{max_perm_len}, sep=' ')", workers)

    if found:
        print(f"\n✓ ПАРОЛЬ НАЙДЕН: {repr(found)}")
        return

    # Шаг 3: перестановки с другим разделителем
    if not deep:
        for sep in ["-", ""]:
            perms_sep = perm_variants(max_len=3, sep=sep)
            found = search(perms_sep, f"Перестановки r=2..3 sep={repr(sep)}", workers)
            if found:
                print(f"\n✓ ПАРОЛЬ НАЙДЕН: {repr(found)}")
                return

    print("\nНичего не найдено.")


if __name__ == "__main__":
    main()
