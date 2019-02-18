# Binaries for use with OSS-Fuzz
#
# Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
#

include ../Makedefs


TARGETS	=	ipp_read_fuzz
OBJS	=	ipp_read_fuzz.o


#
# Make all targets...
#

all:	$(TARGETS)


#
# Make library targets...
#

libs:


#
# Make unit tests...
#

unittests:


#
# Clean all object files...
#

clean:
	$(RM) $(OBJS) $(TARGETS)


#
# Update dependencies (without system header dependencies...)
#

depend:
	$(CC) -MM $(ALL_CFLAGS) $(OBJS:.o=.c) >Dependencies

fuzz: ipp_read_fuzz

#
# ipp_read_fuzz
#

ipp_read_fuzz:	ipp_read_fuzz.cxx ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CXX) -I.. -L../cups -lcups -fsanitize=fuzzer -o ipp_read_fuzz ipp_read_fuzz.cxx 


#
# Dependencies...
#

include Dependencies
