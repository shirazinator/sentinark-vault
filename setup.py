from setuptools import setup, find_packages

setup(
    name="sentinark-vault",
    version="1.0.0",
    author="Shiraz",
    description="Zero-Knowledge Password Entropy, Breach Vulnerability & Hardware Crack-Time Auditor",
    packages=find_packages(),
    install_requires=[
        "Flask>=3.0.0"
    ],
    entry_points={
        "console_scripts": [
            "sentinark-vault=sentinark_vault.cli:main",
            "sentinark-vault-web=sentinark_vault.web_app:run_server"
        ]
    },
    python_requires=">=3.8",
)
