import base64
import hashlib
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip84, Bip84Coins, Bip44Changes


def get_address_from_file(file_name, passphrase=""):

    with open(file_name, "rb") as file:
        file_content = file.read()
    file_base64 = base64.b64encode(file_content)

    # Check and remove additional data if present
    if b"," in file_base64:
        file_base64 = file_base64.split(b",", 1)[1]

    # Create SHA256 hash of the file
    file_hash = hashlib.sha256(file_base64).digest()

    # Convert hash to mnemonic
    mnemonic = Bip39MnemonicGenerator().FromEntropy(file_hash)

    # Generate seed from mnemonic
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)

    # Create BIP84 object for Bitcoin
    bip84_obj = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)

    # Generate addresses from key derivation paths
    wallet = bip84_obj.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

    wif = wallet.PrivateKey().ToWif()
    address = wallet.PublicKey().ToAddress()

    return address, wif


if __name__ == "__main__":

    filename = "kitten.jpeg"
    passphrase = ""

    address = get_address_from_file(filename, passphrase)
    print("----------------------------------------------------------")
    print(f"public address: {address[0]}")
    print(f"private wif key: {address[1]}")
    print(f"passphrase: {passphrase}")
