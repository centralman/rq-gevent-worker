from setuptools import setup

setup(
    name='rq-gevent-worker',
    version='0.1.2',
    scripts=['rq_gevent_worker.py'],
    entry_points={
        'console_scripts': [
            'rqgeventworker=rq_gevent_worker:main',
            ]
        },
    url='https://github.com/zhangliyong/rq-gevent-worker',
    license='BSD',
    author='Lyon Zhang',
    author_email='lyzhang87@gmail.com',
    description='Implement a new worker based on gevent',
    install_requires=['rq >= 0.4.6', 'gevent >= 1.0'],
)