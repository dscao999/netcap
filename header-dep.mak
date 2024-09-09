%.o: %.c
	$(COMPILE.c) -MMD -MP $< -o $@
#	@sed -E -e 's/\/usr\/include(\/[a-z][-a-z0-9_.]*){1,16}//g' \
#		-e 's/\/usr\/lib(\/[a-z][-a-z0-9_.]*){1,16}//g' \
#		-e '/^ *:$$/d' -e '/^ *\\$$/d' -i $(<:.c=.d)

csrcs = $(wildcard *.c)
cdeps = $(csrcs:.c=.d)

-include $(cdeps)
