from distutils.core import setup, Extension

setup(name="psvmi", version="0.1",
      py_modules = ['psvmi'],
	ext_modules = [Extension("_psvmi", ["psvmi.c", "walk_page_tables.c"])])
