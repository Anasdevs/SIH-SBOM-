import re
import requests

def fetch_vulnerabilities(lib):
    url = f"https://libraries.io/api/search?q={lib}&api_key=4d2c63aef358f7c92aad8b15a30b7fbd"
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()[0]
    else:
        print(f"Error fetching vulnerabilities: {response.status_code}")
        return None
# print(fetch_vulnerabilities("pandas"))

def get_packages(file_path):
    with open(file_path, 'r') as file:
        file_content = file.read()

    pattern = re.compile(r"PKG_NAME_ALIASES='(.*?)'", re.DOTALL)
    match = pattern.search(file_content)

    if match:
        aliases_str = match.group(1)
        aliases_list = [alias.strip() for alias in aliases_str.split(',')]

        for alias in aliases_list:
            print(alias)
            return aliases_list
    else:
        print("PKG_NAME_ALIASES not found in the file.")
        return []

def base_reader(file_path):
    # Open the file and read its content
    with open(file_path, 'r') as file:
        file_content = file.read()

    # Define a regular expression pattern to extract distro specs
    pattern = re.compile(r"DISTRO_NAME='(.*?)'\s*\nDISTRO_VERSION=(.*?)\s*\nDISTRO_BINARY_COMPAT='(.*?)'\s*\nDISTRO_FILE_PREFIX='(.*?)'\s*\nDISTRO_COMPAT_VERSION='(.*?)'\s*\nDISTRO_XORG_AUTO='(.*?)'\s*\nDISTRO_DB_SUBNAME='(.*?)'", re.DOTALL)

    # Find the match in the file content
    match = pattern.search(file_content)

    # Check if a match is found
    res= {}
    if match:
        distro_name = match.group(1)
        distro_version = match.group(2)
        distro_binary_compat = match.group(3)
        distro_file_prefix = match.group(4)
        distro_compat_version = match.group(5)
        distro_xorg_auto = match.group(6)
        distro_db_subname = match.group(7)

        # Print the extracted information
        res["Distro Name:"]=distro_name
        res["Distro Version:"]= distro_version
        res["Distro Binary Compatibility:"]=distro_binary_compat
        res["Distro File Prefix:"]= distro_file_prefix
        res["Distro Compatibility Version:"]=distro_compat_version
        res["Distro Xorg Auto:"]=distro_xorg_auto
        res["Distro DB Subname:"]= distro_db_subname
        print(res)
        return res
    else:
        print("Distro specs not found in the file.")
        return {}

