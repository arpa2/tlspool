# add_custom_target?
# add_custom_command(TARGET libtlspool-python
# POST_BUILD
# COMMAND CFLAGS=I${CMAKE_SOURCE_DIR}/include python setup.py build)
# 
# add_dependencies

# install(CODE "execute_process COMMAND CFLAGS=-I${CMAKE_SOURCE_DIR}/include python setup.py install")
# install(CODE "execute_process(COMMAND CFLAGS=-I${CMAKE_SOURCE_DIR}/include python setup.py install)")
install(CODE "execute_process(COMMAND python setup.py install WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})")

install(PROGRAMS webdemo.py
	DESTINATION /usr/local/bin)
