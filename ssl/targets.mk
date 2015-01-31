#
#    targets.mk
#
#    $Source: /usr/local/CVS/ssldump/ssl/targets.mk,v $
#    $Revision: 1.2 $
#    $Date: 2001/12/08 14:57:51 $
#    $Name:  $
#    $Disclaimer$
#
#    Copyright (C) 1999, Terisa Systems, Inc.
#    All Rights Reserved.
#
#    ekr@terisa.com
#



#
#    CONFIGURE USER-DEFINED MAKE ENVIRONMENT
#
#    These fields are specified by the user.  The remainder of
#    this file is generated from this user-specified information.
#
# ANALYZE_SSL_DEFINES:
#    cpp defines, with the -D flag preceeding each
#
# ANALYZE_SSL_INCLUDES:
#    cpp include directories, with the -I flag preceeding each
#
# ANALYZE_SSL_INTERNAL:
#    headers files which are local to a specific module directory,
#    and should not be used by other parts of the toolkit or by
#    the user
#
# ANALYZE_SSL_LIBNAME:
#    the library associated with this module directory, used in
#    most cases for debugging purposes
#
# ANALYZE_SSL_LIBPATHS:
#    link-time directories to search for libraries, with the -L flag
#    preceeding each
#
# ANALYZE_SSL_LIBRARIES:
#    link-time libraries, with the -l flag preceeding each
#
# ANALYZE_SSL_LOCALFLAGS:
#    compile-time flags specific to compiling only the files in
#    this module directory--this variable should only be set in
#    extremely exceptional cases
#
# ANALYZE_SSL_MAKEFILES:
#    the makefiles
#
# ANALYZE_SSL_PREFIX:
#    defines the module name, which also serves as the
#    prefix for all the variable names defined in this file
#
# ANALYZE_SSL_PRIVATE:
#    the private, for-toolkit-use-only API header files
#
# ANALYZE_SSL_PROGRAMS:
#    programs to build
#
# ANALYZE_SSL_PUBLIC:
#    the header files that define the public API for the toolkit
#    and any other 'public' files that should be copied to
#    the build directory
#
# ANALYZE_SSL_SOURCES:
#    the source files to compile to object
#
ANALYZE_SSL_DEFINES       =
ANALYZE_SSL_INCLUDES      = -I$(ANALYZE_SSL_SRCDIR) 
ANALYZE_SSL_INTERNAL      =
ANALYZE_SSL_LIBNAME       = 
ANALYZE_SSL_LIBPATHS      =
ANALYZE_SSL_LIBRARIES     =
ANALYZE_SSL_LOCALFLAGS    =
ANALYZE_SSL_MAKEFILES     =
ANALYZE_SSL_PREFIX        = ANALYZE_SSL 
ANALYZE_SSL_PRIVATE       = ssl_analyze.h 
ANALYZE_SSL_PROGRAMS      =
ANALYZE_SSL_PUBLIC        =
ANALYZE_SSL_SOURCES       = ciphersuites.c ssl.enums.c ssl_analyze.c \
                            ssl_rec.c ssldecode.c sslprint.c sslxprint.c 



#
#    CONFIGURE AUTOMATICALLY-GENERATED MAKE ENVIRONMENT
#
# ANALYZE_SSL_OBJECTS:
#    object files to build
#
# ANALYZE_SSL_UNUSED:
#    obsolete files in the module directory that are not
#    used during the build process
#
# ANALYZE_SSL_USED:
#    all files in the module directory that are used
#    during the build process
#
ANALYZE_SSL_OBJECTS       = ciphersuites.$(OBJSUFFIX) ssl.enums.$(OBJSUFFIX) \
                            ssl_analyze.$(OBJSUFFIX) ssl_rec.$(OBJSUFFIX) \
                            ssldecode.$(OBJSUFFIX) sslprint.$(OBJSUFFIX) \
                            sslxprint.$(OBJSUFFIX) 
ANALYZE_SSL_UNUSED        = Makefile lex.yy.c main.c ssl.enums.h ssl_enum.c \
                            ssl_h.h sslciphers.h ssldecode.h sslprint.h \
                            sslxprint.h targets.mk y.tab.c y.tab.h 
ANALYZE_SSL_USED          = $(ANALYZE_SSL_INTERNAL:%=$(ANALYZE_SSL_SRCDIR)%) \
                            $(ANALYZE_SSL_MAKEFILES:%=$(ANALYZE_SSL_SRCDIR)%) \
                            $(ANALYZE_SSL_PRIVATE:%=$(ANALYZE_SSL_SRCDIR)%) \
                            $(ANALYZE_SSL_PUBLIC:%=$(ANALYZE_SSL_SRCDIR)%) \
                            $(ANALYZE_SSL_SOURCES:%=$(ANALYZE_SSL_SRCDIR)%) 



#
#    NOTES
#
#    The following variables may be used during the build process,
#    but are not defined in this file.  If they are to be set
#    to something other than the default blank, then they must
#    be set by the calling make system.
#
# ANALYZE_SSL_SRCDIR:
#    if the build target directory is different from the
#    module directory (the source directory), then this
#    variable contains the relative or full path of
#    the module directory
#
# LIBARS:
#    the library archive files (with fully-specified paths) that
#    executables built from this module directory depend upon
#
# LIBPATHS:
#    the paths to search for library archives (specified with
#    the -L)
#
# LIBRARIES:
#    the libraries to use while building executables from
#    this module directory (specified with the -l)
#



#
#    GLOBAL ENVIRONMENT
#
DEFINES                  += $(ANALYZE_SSL_DEFINES) 
INCLUDES                 += $(ANALYZE_SSL_INCLUDES) 
LIBPATHS                 += $(ANALYZE_SSL_LIBPATHS) 
LIBRARIES                += $(ANALYZE_SSL_LIBRARIES) 
OBJECTS                  += $(ANALYZE_SSL_OBJECTS) 
PUBLIC                   += $(ANALYZE_SSL_PUBLIC) 



#
#    GENERIC DEPENDENCIES
#
# default:
#    default dependency, must be the first dependency in this makefile
#
# all:
#    build everything in this module directory
#
# build:
#    make only the toolkit build files of this module directory
#
# ci:
#    perform an RCS check-in of this module directory
#
# clean:
#    remove the compiled files
#
# clean_public:
#    remove the public header files that have been copied
#    to a public build directory
#
# objects:
#    build the object files (this dependency is used for
#    building the toolkit library)
#
# private:
#    build only the private API header files
#
# public:
#    build only the public API header files
#
default:                    $(ANALYZE_SSL_LIBNAME)
default:                    $(ANALYZE_SSL_PROGRAMS)

all:                        $(ANALYZE_SSL_PUBLIC)
all:                        $(ANALYZE_SSL_OBJECTS)
all:                        $(ANALYZE_SSL_LIBNAME)
all:                        $(ANALYZE_SSL_PROGRAMS)
build:                      $(ANALYZE_SSL_PUBLIC)
build:                      $(ANALYZE_SSL_OBJECTS)
ci:                         analyze_ssl_ci
clean:                      analyze_ssl_clean
clean_public:               analyze_ssl_clean_public
objects:                    $(ANALYZE_SSL_OBJECTS)
private:                    $(ANALYZE_SSL_PRIVATE)
public:                     $(ANALYZE_SSL_PUBLIC)



#
#    LOCAL UTILITY DEPENDENCIES
#
#    utility dependencies are necessary because of some
#    make-isms having to do with dependencies
#

analyze_ssl_ci:
	$(CI) $(CIFLAGS) $(ANALYZE_SSL_USED)

analyze_ssl_clean:
	$(RM) $(RMFLAGS) $(ANALYZE_SSL_OBJECTS) $(ANALYZE_SSL_LIBNAME) $(ANALYZE_SSL_PROGRAMS)

analyze_ssl_clean_public:
	$(RM) $(RMFLAGS) $(ANALYZE_SSL_PUBLIC)

analyze_ssl_objects: $(ANALYZE_SSL_OBJECTS)

analyze_ssl_programs: $(ANALYZE_SSL_PROGRAMS)

analyze_ssl_public: $(ANALYZE_SSL_PUBLIC)



#
#    BUILD DEPENDENCIES
#
#    build dependencies invoke the rule used to build each
#    class of file
#

$(ANALYZE_SSL_LIBNAME):
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

$(ANALYZE_SSL_OBJECTS):
	$(COMPILE.c) $(ANALYZE_SSL_SRCDIR)$(@:%.o=%.c) $(DEFINES) $(INCLUDES) $(ANALYZE_SSL_LOCALFLAGS)
 
$(ANALYZE_SSL_PUBLIC):
	$(CP) $(CPFLAGS) $(ANALYZE_SSL_SRCDIR)$@ $@

$(ANALYZE_SSL_PROGRAMS):
	$(LINK.c) $@.$(OBJSUFFIX) $(LDLIBS) $(LIBS) $(LIBRARIES) $(LIBPATHS)
#LIBS above is obsolete (use LIBARARIES instead)



#
#    FILE DEPENDENCIES
#
#    file dependencies state, for each file that is built,
#    which file(s) it depends upon
#

ciphersuites.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)ciphersuites.c

ssl.enums.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)ssl.enums.h
ssl.enums.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)ssl.enums.c

ssl_analyze.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)ssl_analyze.h
ssl_analyze.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)ssl_analyze.c

ssl_rec.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)ssl_rec.c

ssldecode.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)ssldecode.h
ssldecode.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)ssldecode.c

sslprint.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)sslprint.h
sslprint.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)sslprint.c

sslxprint.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)sslxprint.h
sslxprint.$(OBJSUFFIX): $(ANALYZE_SSL_SRCDIR)sslxprint.c

$(ANALYZE_SSL_LIBNAME): $(ANALYZE_SSL_OBJECTS)
