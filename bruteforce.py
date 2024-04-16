from numerize import numerize
from pathlib import Path
from bip_utils import Bip39SeedGenerator, Bip84, Bip84Coins, Bip44Changes
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


def find_passphrase():
    start_dir = Path("wordlists")

    success_files = []
    try:
        with open("stats.txt", "r") as f:
            success_files = f.readlines()
    except FileNotFoundError:
        pass

    txt_files = list(start_dir.rglob("*.txt"))

    for file_path in txt_files:
        if file_path in success_files:
            continue
        print()
        print("Checking file: " + str(file_path))

        i = 0
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                i += 1
                word = line.strip()

                result = get_address_with_kitten_mnemonic(word)

                if result == BTC_ADDRESS:
                    print("-------------------------")
                    print("Passphrase found: " + word)
                    print("-------------------------")
                    return

                if i % 1000 == 0:
                    sys.stdout.write(f"\rProgress: {numerize.numerize(i)}")

        with open("stats.txt", "a", encoding="utf-8") as f:
            f.write(f"{file_path}\n")

    print("Passphrase not found")


if __name__ == "__main__":
    find_passphrase()
