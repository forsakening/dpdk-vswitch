all:vswitch vconsole

vswitch:lib_httpserver
	make -f Makefile_vswitch clean
	make -f Makefile_vswitch

lib_httpserver:
	make -f Makefile_httpserver

vconsole:
	make -f Makefile_vconsole clean
	make -f Makefile_vconsole
clean:
	make -f Makefile_vswitch clean
	make -f Makefile_vconsole clean
