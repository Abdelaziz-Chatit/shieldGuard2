import os
import sys
try:
    from urllib.request import urlretrieve
except ImportError:
    from urllib import urlretrieve

BASE_URL = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/"
FILES = [
    "c2-iocs.txt",
    "filename-iocs.txt",
    "hash-iocs.txt",
    "keywords.txt"
]

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = os.path.join(base_dir, 'signatures', 'iocs')
    os.makedirs(target_dir, exist_ok=True)

    for filename in FILES:
        url = BASE_URL + filename
        dest = os.path.join(target_dir, filename)
        try:
            print(f'Downloading {filename}...')
            urlretrieve(url, dest)
            print(f'  saved to {dest}')
        except Exception as e:
            print(f'Failed to download {filename}: {e}')
            sys.exit(1)

    print('Download complete. Restart your FastAPI backend to load the new IOC files.')

if __name__ == '__main__':
    main()
