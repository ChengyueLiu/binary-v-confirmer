import subprocess
from dataclasses import dataclass

import requests


@dataclass
class Package:
    """
    {'Description': 'The Open Source toolkit for Secure Sockets Layer and Transport Layer Security (Android, aarch64)', 'FirstSubmitted': 1544556720, 'ID': 1403450, 'LastModified': 1706975877, 'Maintainer': 'Martchus', 'Name': 'android-aarch64-openssl', 'NumVotes': 0, 'OutOfDate': None, 'PackageBase': 'android-aarch64-openssl', 'PackageBaseID': 137991, 'Popularity': 0, 'URL': 'https://www.openssl.org', 'URLPath': '/cgit/aur.git/snapshot/android-aarch64-openssl.tar.gz', 'Version': '3.2.1-1'}
    """
    package_base_id: int
    name: str
    version: str
    maintainer: str
    description: str
    first_submitted: int
    last_modified: int
    num_votes: int
    out_of_date: str
    package_base: str
    popularity: int
    url: str
    url_path: str

    @classmethod
    def init_from_dict(cls, data):
        return cls(
            name=data['Name'],
            description=data['Description'],
            first_submitted=data['FirstSubmitted'],
            last_modified=data['LastModified'],
            maintainer=data['Maintainer'],
            num_votes=data['NumVotes'],
            out_of_date=data['OutOfDate'],
            package_base=data['PackageBase'],
            package_base_id=data['PackageBaseID'],
            popularity=data['Popularity'],
            url=data['URL'],
            url_path=data['URLPath'],
            version=data['Version']
        )


def compile_package(package_name, compiler=None, optimization_level=None):
    # 构建 Docker 镜像（如果尚未构建）
    subprocess.run(["docker-compose", "build"], check=True)

    # 运行编译脚本
    command = ["docker-compose", "run", "arch-compiler", "/bin/bash", "-c",
               f"./compile.sh {package_name} {compiler or ''} {optimization_level or ''}"]
    subprocess.run(command, check=True)


def search_packages(query) -> list[Package]:
    url = "https://aur.archlinux.org/rpc/?v=5&type=search&arg=" + query
    response = requests.get(url)
    packages = response.json().get('results', [])

    packages = [Package.init_from_dict(package) for package in packages]
    return packages


def main():
    # 示例：搜索包含 "openssl" 关键词的包
    packages = search_packages("openssl")
    for p in packages:
        print(p.name, p.version, p.maintainer)

    # 示例：编译名为 "openssl" 的包，使用 gcc 编译器和优化等级 2
    # compile_package("openssl", "gcc", "2")


if __name__ == '__main__':
    main()
