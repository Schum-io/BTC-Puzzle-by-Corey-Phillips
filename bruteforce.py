import os

from numerize import numerize
from pathlib import Path
from bip_utils import Bip39SeedGenerator, Bip84, Bip84Coins, Bip44Changes
from concurrent.futures import ProcessPoolExecutor
import sys

BTC_ADDRESS = "bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r"  # 0.1 btc address with balance in puzzle
EMPTY_ADDRESS = "bc1q57euh23y3qs2f9d5mtwpax5lqecfvrdkqce82a"  # just empty kitten address in puzzle

KITTEN_MNEMONIC = "blossom educate state course sick fresh color divide number soap please pull glide weather join grit depart dynamic tenant leopard alter piano slight room"


def get_address_with_kitten_mnemonic(passphrase=""):
    # kitten mnemonic

    # Generate seed from mnemonic
    seed_bytes = Bip39SeedGenerator(KITTEN_MNEMONIC).Generate(passphrase)

    # Create BIP84 object for Bitcoin
    bip84_obj = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)

    # Generate addresses from key derivation paths
    wallet = bip84_obj.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

    return wallet.PublicKey().ToAddress()


def find_passphrase(filename):
    process_pid = os.getpid()
    print(f"Start process {process_pid} with file {filename}")

    i = 0
    with open(filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            i += 1
            base_word = line.strip()
            variants = {base_word, base_word.lower(), base_word.upper(), base_word.capitalize()}

            for word in variants:
                result = get_address_with_kitten_mnemonic(word)

                if result.lower() == BTC_ADDRESS.lower():
                    print("-------------------------")
                    print("Passphrase found: " + word)
                    print("-------------------------")
                    sys.exit()

            if i % 1000 == 0:
                sys.stdout.write(f"\rProgress: {numerize.numerize(i)}. {filename}")

    with open("stats.txt", "a", encoding="utf-8") as f:
        f.write(f"{filename}\n")
        print("File processed: " + filename)


def find_passphrase_threaded():
    start_dir = Path("wordlists")
    cpu_count = os.cpu_count()
    max_workers = int(cpu_count / 3)

    success_files = set()
    try:
        with open("stats.txt", "r") as f:
            success_files = {line.strip() for line in f.readlines()}
    except FileNotFoundError:
        pass

    txt_files = list(start_dir.rglob("*.txt"))

    files = []
    for file_path in txt_files:
        if str(file_path) in success_files:
            continue
        files.append(file_path)

    print(f"CPU Count: {cpu_count}")
    print(f"Workers count: {max_workers}")
    print(f"files count: {len(files)}")

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(find_passphrase, file_path) for file_path in files]
        try:
            for future in futures:
                future.result()
        except KeyboardInterrupt:
            print("Main process received CTRL+C! Sending shutdown signal to child processes...")
        finally:
            print("Shutting down executor...")
            executor.shutdown(wait=True)
            print("All processes were successfully terminated.")


def find():
    word_count = 0
    with open("wordlists/words.txt", "r", encoding="utf-8") as file:
        for file_line in file:
            lines = file_line.split()
            for line in lines:
                text = line.strip()
                words = [text, text.lower(), text.upper()]
                for word in words:
                    word_count += 1
                    result = get_address_with_kitten_mnemonic(word)
                    if result == BTC_ADDRESS:
                        print("-------------------------")
                        print("Passphrase found: " + word)
                        print("-------------------------")
                        return

    print(f"Word count: {word_count}")


if __name__ == "__main__":
    # find()
    find_passphrase_threaded()
