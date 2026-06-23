from setuptools import setup

setup(
    name="dockershield",
    version="1.0.0",
    description="Docker Image Security Scanner - CVEs, secrets, malware, misconfigurations",
    author="Krishna Chaithanya Yada",
    author_email="yadakrishna245@gmail.com",
    url="https://github.com/yadakrishna245/DockerShield",
    py_modules=["dockershield"],
    install_requires=["docker>=7.0.0", "rich>=13.0.0"],
    entry_points={"console_scripts": ["dockershield=dockershield:main"]},
    python_requires=">=3.9",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
