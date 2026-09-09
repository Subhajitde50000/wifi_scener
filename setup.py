from setuptools import setup, find_packages

setup(
    name="wifiscanner",
    version="4.1.0",
    description="Advanced passive Wi-Fi survey, client-attribution and CSV export engine",
    packages=find_packages(include=["wifiscanner", "wifiscanner.*"]),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={"full": ["scapy>=2.5.0", "rich>=14.1.0", "sqlalchemy>=2.0.0"]},
    entry_points={"console_scripts": ["wifiscanner=wifiscanner.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Monitoring",
        "Intended Audience :: System Administrators",
    ],
)
