#!/usr/bin/env python3

import pathlib
import setuptools

# The directory containing this file
CURR_DIR = pathlib.Path(__file__).parent

# The text of the README file
README = (CURR_DIR / "README.md").read_text()

setuptools.setup(
     name='iris_cortexanalyzer_module',
     version='1.1',
     packages=['iris_cortexanalyzer_module', 'iris_cortexanalyzer_module.cortexanalyzer_handler'],
     author="VLK14",
     author_email="jorge.loureiro@ipb.pt",
     description="iris-cortexanalyzer-module is an IRIS pipeline/processor module created with https://github.com/dfir-iris/iris-skeleton-module. This version of the module is forked from https://github.com/socfortress/iris-cortexanalyzer-module. It offers extra functionalities, like multi-analyzer execution, separate job reports, and the addition of tags to the IOCs with the results of the analysis.",
     long_description=README,
     long_description_content_type="text/markdown",
     url="https://10.1.69.252/vlk/iris_cortexanalyzer_module",
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: LGLP 3.0 License",
         "Operating System :: OS Independent",
     ],
     install_requires=['cortex4py~=2.1', 'setuptools>=65.5.1', 'iris-interface==1.2.0']
 )