#!/usr/bin/env python

"""
setup.py file for TLS Pool module in Python
"""

from distutils.core import setup, Extension


tlspool_module = Extension('_tlspool',
                           sources=['tlspool.c'],
                           )

setup (name = 'tlspool',
       version = '0.0',
       author      = "Rick van Rein",
       description = """Using TLS Pool, adding security to applications is made terribly simple.  The only concern to the application programmer will be about identities exchanged.  Anything security-related is delegated to the specialist, the TLS Pool.""",
       ext_modules = [tlspool_module],
       py_modules = ["tlspool"],
       )
