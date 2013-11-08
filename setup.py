from setuptools import setup, find_packages
import sys, os

version = '0.0'

setup(name='taste',
      version=version,
      description="A simple HTTP stream taster.",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Russell Sim',
      author_email='russell.sim@gmail.com',
      url='',
      license='GPLv3',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          # -*- Extra requirements: -*-
          'pynids',
      ],
      entry_points="""
      # -*- Entry points: -*-
      [console_scripts]
      taste = taste.tongue:main

      """,
      )
