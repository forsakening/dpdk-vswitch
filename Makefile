vswitch:
	make -f Makefile_vswitch clean
	make -f Makefile_vswitch
vconsole:
	make -f Makefile_vconsole clean
	make -f Makefile_vconsole
clean:
	make -f Makefile_vswitch clean
	make -f Makefile_vconsole clean
