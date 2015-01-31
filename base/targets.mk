#
#    targets.mk
#
#    $Source: /usr/local/CVS/ssldump/base/targets.mk,v $
#    $Revision: 1.3 $
#    $Date: 2002/08/17 01:33:16 $
#    $Name:  $
#    $Disclaimer$
#
#    Copyright (C) 2001, Terisa Systems, Inc.
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
# ANALYZE_DEFINES:
#    cpp defines, with the -D flag preceeding each
#
# ANALYZE_INCLUDES:
#    cpp include directories, with the -I flag preceeding each
#
# ANALYZE_INTERNAL:
#    headers files which are local to a specific module directory,
#    and should not be used by other parts of the toolkit or by
#    the user
#
# ANALYZE_LIBNAME:
#    the library associated with this module directory, used in
#    most cases for debugging purposes
#
# ANALYZE_LIBPATHS:
#    link-time directories to search for libraries, with the -L flag
#    preceeding each
#
# ANALYZE_LIBRARIES:
#    link-time libraries, with the -l flag preceeding each
#
# ANALYZE_LOCALFLAGS:
#    compile-time flags specific to compiling only the files in
#    this module directory--this variable should only be set in
#    extremely exceptional cases
#
# ANALYZE_MAKEFILES:
#    the makefiles
#
# ANALYZE_PREFIX:
#    defines the module name, which also serves as the
#    prefix for all the variable names defined in this file
#
# ANALYZE_PRIVATE:
#    the private, for-toolkit-use-only API header files
#
# ANALYZE_PROGRAMS:
#    programs to build
#
# ANALYZE_PUBLIC:
#    the header files that define the public API for the toolkit
#    and any other 'public' files that should be copied to
#    the build directory
#
# ANALYZE_SOURCES:
#    the source files to compile to object
#
ANALYZE_DEFINES           =
ANALYZE_INCLUDES          = -I$(ANALYZE_SRCDIR) 
ANALYZE_INTERNAL          =
ANALYZE_LIBNAME           = 
ANALYZE_LIBPATHS          =
ANALYZE_LIBRARIES         =
ANALYZE_LOCALFLAGS        =
ANALYZE_MAKEFILES         = targets.mk 
ANALYZE_PREFIX            = ANALYZE 
ANALYZE_PRIVATE           = network.h proto_mod.h tcpconn.h tcppack.h 
ANALYZE_PROGRAMS          = 
ANALYZE_PUBLIC            = 
ANALYZE_SOURCES           = network.c pcap-snoop.c proto_mod.c tcpconn.c \
                            tcppack.c 



#
#    CONFIGURE AUTOMATICALLY-GENERATED MAKE ENVIRONMENT
#
# ANALYZE_OBJECTS:
#    object files to build
#
# ANALYZE_UNUSED:
#    obsolete files in the module directory that are not
#    used during the build process
#
# ANALYZE_USED:
#    all files in the module directory that are used
#    during the build process
#
ANALYZE_OBJECTS           = network.$(OBJSUFFIX) pcap-snoop.$(OBJSUFFIX) \
                            proto_mod.$(OBJSUFFIX) tcpconn.$(OBJSUFFIX) \
                            tcppack.$(OBJSUFFIX) 
ANALYZE_UNUSED            = common.c debug.c debug.h print_utils.c \
                            print_utils.h 
ANALYZE_USED              = $(ANALYZE_INTERNAL:%=$(ANALYZE_SRCDIR)%) \
                            $(ANALYZE_MAKEFILES:%=$(ANALYZE_SRCDIR)%) \
                            $(ANALYZE_PRIVATE:%=$(ANALYZE_SRCDIR)%) \
                            $(ANALYZE_PUBLIC:%=$(ANALYZE_SRCDIR)%) \
                            $(ANALYZE_SOURCES:%=$(ANALYZE_SRCDIR)%) 



#
#    NOTES
#
#    The following variables may be used during the build process,
#    but are not defined in this file.  If they are to be set
#    to something other than the default blank, then they must
#    be set by the calling make system.
#
# ANALYZE_SRCDIR:
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
DEFINES                  += $(ANALYZE_DEFINES) 
INCLUDES                 += $(ANALYZE_INCLUDES) 
LIBPATHS                 += $(ANALYZE_LIBPATHS) 
LIBRARIES                += $(ANALYZE_LIBRARIES) 
OBJECTS                  += $(ANALYZE_OBJECTS) 
PUBLIC                   += $(ANALYZE_PUBLIC) 



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
default:                    $(ANALYZE_LIBNAME)
default:                    $(ANALYZE_PROGRAMS)

all:                        $(ANALYZE_PUBLIC)
all:                        $(ANALYZE_OBJECTS)
all:                        $(ANALYZE_LIBNAME)
all:                        $(ANALYZE_PROGRAMS)
build:                      $(ANALYZE_PUBLIC)
build:                      $(ANALYZE_OBJECTS)
ci:                         analyze_ci
clean:                      analyze_clean
clean_public:               analyze_clean_public
objects:                    $(ANALYZE_OBJECTS)
private:                    $(ANALYZE_PRIVATE)
public:                     $(ANALYZE_PUBLIC)



#
#    LOCAL UTILITY DEPENDENCIES
#
#    utility dependencies are necessary because of some
#    make-isms having to do with dependencies
#

analyze_ci:
	$(CI) $(CIFLAGS) $(ANALYZE_USED)

analyze_clean:
	$(RM) $(RMFLAGS) $(ANALYZE_OBJECTS) $(ANALYZE_LIBNAME) $(ANALYZE_PROGRAMS)

analyze_clean_public:
	$(RM) $(RMFLAGS) $(ANALYZE_PUBLIC)

analyze_objects: $(ANALYZE_OBJECTS)

analyze_programs: $(ANALYZE_PROGRAMS)

analyze_public: $(ANALYZE_PUBLIC)



#
#    BUILD DEPENDENCIES
#
#    build dependencies invoke the rule used to build each
#    class of file
#

$(ANALYZE_LIBNAME):
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

$(ANALYZE_OBJECTS):
	$(COMPILE.c) $(ANALYZE_SRCDIR)$(@:%.$(OBJSUFFIX)=%.c) $(DEFINES) $(INCLUDES) $(ANALYZE_LOCALFLAGS)

$(ANALYZE_PUBLIC):
	$(CP) $(CPFLAGS) $(ANALYZE_SRCDIR)$@ $@

$(ANALYZE_PROGRAMS):
	$(LINK.c) -o $@ $@.$(OBJSUFFIX) $(LDLIBS) $(LIBS) $(LIBRARIES) $(LIBPATHS)
#LIBS above is obsolete (use LIBARARIES instead)



#
#    FILE DEPENDENCIES
#
#    file dependencies state, for each file that is built,
#    which file(s) it depends upon
#

network.$(OBJSUFFIX): $(ANALYZE_SRCDIR)network.h
network.$(OBJSUFFIX): $(ANALYZE_SRCDIR)network.c

pcap-snoop.$(OBJSUFFIX): $(ANALYZE_SRCDIR)pcap-snoop.c

proto_mod.$(OBJSUFFIX): $(ANALYZE_SRCDIR)proto_mod.h
proto_mod.$(OBJSUFFIX): $(ANALYZE_SRCDIR)proto_mod.c

tcpconn.$(OBJSUFFIX): $(ANALYZE_SRCDIR)tcpconn.h
tcpconn.$(OBJSUFFIX): $(ANALYZE_SRCDIR)tcpconn.c

tcppack.$(OBJSUFFIX): $(ANALYZE_SRCDIR)tcppack.h
tcppack.$(OBJSUFFIX): $(ANALYZE_SRCDIR)tcppack.c

$(ANALYZE_LIBNAME): $(ANALYZE_OBJECTS)
