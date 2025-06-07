# setup.py
from setuptools import setup, find_packages

setup(
    name="auth-service",
    version="1.0.0",
    packages=find_packages(),
    extras_require={
        "dev": [
            "flake8>=6.0.0",
            "bandit>=1.7.5",
        ],
    },
)
