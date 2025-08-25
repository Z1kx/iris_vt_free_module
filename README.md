## Installation 
1. Git clone this repository
2. Build the wheel : ``python3 setup.py bdist_wheel`` 
3. Copy the wheel into the IRIS app docker container ``docker cp iris_vt_free_module-XX-py3-none-any.whl container:/iriswebapp/dependencies/``
4. Get an interactive shell on the docker : ``docker exec -it container /bin/sh``
5. Install the new package ``pip3 install dependencies/iris_vt_free_module-XX-py3-none-any.whl``
