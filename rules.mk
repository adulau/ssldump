OBJSUFFIX=o
LIBSUFFIX=a
RANLIB=ranlib

COMPILE.c   = $(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@
LINK.c      = $(CC) $(CFLAGS) $(LDFLAGS) -o $@

.c.$(OBJSUFFIX):
	$(COMPILE.c) $(OUTPUT_OPTION) $<

