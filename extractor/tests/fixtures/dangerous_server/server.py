import os
import subprocess
import pickle
import shutil
from pathlib import Path

import requests
import httpx
from aiohttp import ClientSession

API_KEY = os.environ.get("API_KEY")
DB_URL = os.environ.get("DATABASE_URL")

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

def delete_file(path):
    os.remove(path)

def run_command(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True)

def fetch_data(url):
    return requests.get(url)

def load_config(data):
    return pickle.loads(data)
