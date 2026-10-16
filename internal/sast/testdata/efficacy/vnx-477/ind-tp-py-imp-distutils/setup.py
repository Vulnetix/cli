import os
~>import imp
~>from distutils.core import setup

here = os.path.dirname(__file__)
setup(name="pkg", version="1.4.0", package_dir={"": here})
