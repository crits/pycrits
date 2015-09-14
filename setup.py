from setuptools import setup

setup(
    name = "pycrits",
    version = "0.1",
    author = "Wesley Shields",
    author_email = "wxs@atarininja.org",
    description = ("Python interface to CRITs API."),
    license = "BSD",
    keywords = "CRITs",
    url = "https://github.com/crits/pycrits",
    packages=['pycrits'],
    long_description="Python interface to the CRITs API.",
    install_requires=['requests', 'backoff']
)
