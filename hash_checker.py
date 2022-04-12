import requests
import json
import time
from typing import List


def hash_checker(hashes: List, api_key: str):
    ret = {"hashes": []}
    for hash in hashes:
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        url = f"https://www.virustotal.com/api/v3/files/{hash}"
        response = requests.request("GET", url, headers=headers)
        resp_json = json.loads(response.content)
        ret["hashes"].append(resp_json)
        time.sleep(15)
    return ret


hashes = [
    "4c47ca6ecf04cfe312eb276022a0c381",
    "1539b3a5921203f0e2b6c05d692ffa27",
    "f744481a4c4a7c811ffc7dee3b58b1ff",
    "728e5700a401498d91fb83159beec834",
    "D85818E82A6E64CA185EDFDDBA2D1B76",
    "cf94796a07b6082b9e348eef934de97a",
    "1606ab7a54735af654ee6deb7427f652",
    "C9F16F0BE8C77F0170B9B6CE876ED7FB",
    "5fe8dcdfe9e3c4e56e004b2eebf50ab3",
    "41be449f687828466ed7d87f0f30a278",
    "2bec1860499aae1dbcc92f48b276f998",
    "13389d4a2166e054223ccef90324a154",
    "7e459fe092a3f06141605821a63860b96b43fbe7",
    "77b4ffe73491d534946d010bfca138f7",
    "3043fc9dd586cc069e0a7a558d787e69",
    "be65db6f9af2d96db7e3e88df22e183a65fe58f4",
    "26bd36cc57e30656363ca89910579f63",
    "b0a9a175e2407352214b2d005253bc0c",
    "f8cb10b2ee8af6c5555e9cf3701b845f",
    "369072fce5e56a87a35c37496125854a559a6a4b",
    "6c74ff2cc39b5362ee5dec576ece211b",
    "01039a95e0a14767784acc8f07035935",
    "4cbd9a0832dcf23867b092de37c10d9d",
    "42ffc84c6381a18b1f6d000b94c74b09",
    "9018fa0826f237342471895f315dbf39",
    "719cf63a3922953ceaca6fb4dbed6584",
    "f13536685206a94a8d3938266f100bb2dffa740a202283c7ea35c58e6dbbb839",
    "0644e561225ab696a97ba9a77583dcaab4c26ef0379078c65f9ade684406eded",
    "96649c5428c874f2228c77c96526ff3f472bc2425476ad1d882a8b55faa40bf5",
    "E6AC6F18256C4DDE5BF06A9191562F82",
    "44cf0793e05ba843dd53bbc7020e0f1c",
    "A3FCB4D23C3153DD42AC124B112F1BAE",
    "5c3ab475be110ec59257617ee1388e01",
    "c8d86e9f486d23285b744279812ef9047a0908e39656c2ea4cdf3e182f80e11d",
    "41542d11abf5bf4a18332e9c4f2c8d1eb5c7e5d4298749b610d86caaa1acb62c",
    "29b0454db88b634656a3fc7c36f318b126a83ae8fb7f73fe9ff349a8f8536c7b",
    "851ad180447f8ab06ef6877174be1374bd92b44e746f25872e72d984b8eb5ca6",
    "02b95ef7a33a87cc2b3b6fd47db03e711045974e1ecf631d3ba9e076e1e374e9",
]

api_key = ""  # insert api_key here

print(hash_checker(hashes=hashes, api_key=api_key))
