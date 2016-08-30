from setuptools import setup

setup(
    name='nginx_installer',
    version='0.1',
    py_modules=['nginx_installer'],
    install_requires=[
        'click==6.6',
        'pyparsing==2.1.8',
        'requests==2.11.1',
        'semver==2.6.0'
    ],
    entry_points='''
        [console_scripts]
        nginx_installer=nginx_installer:start
    ''',
)
