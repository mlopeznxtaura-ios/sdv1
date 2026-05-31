from setuptools import setup, find_packages

setup(
    name="viabilityscan",
    version="1.0.0",
    description="Repository Viability & Deployment Readiness Engine",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        # Core — zero heavy dependencies for MVP
        # All scanning done with stdlib + optional external tools
    ],
    extras_require={
        "full": [
            "semgrep",
            "checkov",
        ],
        "dashboard": [
            "nicegui>=1.4",
        ],
        "dev": [
            "pytest",
            "pytest-cov",
        ],
    },
    entry_points={
        "console_scripts": [
            "viabilityscan=viabilityscan.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
