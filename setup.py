# setup.py
from setuptools import setup, find_packages

setup(
    name="aspen",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "Click",
        "fastapi",
        "uvicorn",
        "sqlalchemy",
        "python_wireguard",
    ],
    entry_points={
        "console_scripts": [
            "aspen-server=server.cli:cli",
        ],
    },
)
