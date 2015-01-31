#
#    targets.mk
#
#    $Source: /usr/local/CVS/ssldump/null/targets.mk,v $
#    $Revision: 1.1.1.1 $
#    $Date: 2000/10/09 00:45:39 $
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
# ANALYZE_NULL_DEFINES:
#    cpp defines, with the -D flag preceeding each
#
# ANALYZE_NULL_INCLUDES:
#    cpp include directories, with the -I flag preceeding each
#
# ANALYZE_NULL_INTERNAL:
#    headers files which are local to a specific module directory,
#    and should not be used by other parts of the toolkit or by
#    the user
#
# ANALYZE_NULL_LIBNAME:
#    the library associated with this module directory, used in
#    most cases for debugging purposes
#
# ANALYZE_NULL_LIBPATHS:
#    link-time directories to search for libraries, with the -L flag
#    preceeding each
#
# ANALYZE_NULL_LIBRARIES:
#    link-time libraries, with the -l flag preceeding each
#
# ANALYZE_NULL_LOCALFLAGS:
#    compile-time flags specific to compiling only the files in
#    this module directory--this variable should only be set in
#    extremely exceptional cases
#
# ANALYZE_NULL_MAKEFILES:
#    the makefiles
#
# ANALYZE_NULL_PREFIX:
#    defines the module name, which also serves as the
#    prefix for all the variable names defined in this file
#
# ANALYZE_NULL_PRIVATE:
#    the private, for-toolkit-use-only API header files
#
# ANALYZE_NULL_PROGRAMS:
#    programs to build
#
# ANALYZE_NULL_PUBLIC:
#    the header files that define the public API for the toolkit
#    and any other 'public' files that should be copied to
#    the build directory
#
# ANALYZE_NULL_SOURCES:
#    the source files to compile to object
#
ANALYZE_NULL_DEFINES      =
ANALYZE_NULL_INCLUDES     = -I$(ANALYZE_NULL_SRCDIR) 
ANALYZE_NULL_INTERNAL     =
ANALYZE_NULL_LIBNAME      =
ANALYZE_NULL_LIBPATHS     =
ANALYZE_NULL_LIBRARIES    =
ANALYZE_NULL_LOCALFLAGS   =
ANALYZE_NULL_MAKEFILES    = targets.mk 
ANALYZE_NULL_PREFIX       = ANALYZE_NULL 
ANALYZE_NULL_PRIVATE      = null_analyze.h 
ANALYZE_NULL_PROGRAMS     =
ANALYZE_NULL_PUBLIC       =
ANALYZE_NULL_SOURCES      = null_analyze.c 



#
#    CONFIGURE AUTOMATICALLY-GENERATED MAKE ENVIRONMENT
#
# ANALYZE_NULL_OBJECTS:
#    object files to build
#
# ANALYZE_NULL_UNUSED:
#    obsolete files in the module directory that are not
#    used during the build process
#
# ANALYZE_NULL_USED:
#    all files in the module directory that are used
#    during the build process
#
ANALYZE_NULL_OBJECTS      = null_analyze.$(OBJSUFFIX) 
ANALYZE_NULL_UNUSED       =
ANALYZE_NULL_USED         = $(ANALYZE_NULL_INTERNAL:%=$(ANALYZE_NULL_SRCDIR)%) \
                            $(ANALYZE_NULL_MAKEFILES:%=$(ANALYZE_NULL_SRCDIR)%) \
                            $(ANALYZE_NULL_PRIVATE:%=$(ANALYZE_NULL_SRCDIR)%) \
                            $(ANALYZE_NULL_PUBLIC:%=$(ANALYZE_NULL_SRCDIR)%) \
                            $(ANALYZE_NULL_SOURCES:%=$(ANALYZE_NULL_SRCDIR)%) 



#
#    NOTES
#
#    The following variables may be used during the build process,
#    but are not defined in this file.  If they are to be set
#    to something other than the default blank, then they must
#    be set by the calling make system.
#
# ANALYZE_NULL_SRCDIR:
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
DEFINES                  += $(ANALYZE_NULL_DEFINES) 
INCLUDES                 += $(ANALYZE_NULL_INCLUDES) 
LIBPATHS                 += $(ANALYZE_NULL_LIBPATHS) 
LIBRARIES                += $(ANALYZE_NULL_LIBRARIES) 
OBJECTS                  += $(ANALYZE_NULL_OBJECTS) 
PUBLIC                   += $(ANALYZE_NULL_PUBLIC) 



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
default:                    $(ANALYZE_NULL_LIBNAME)
default:                    $(ANALYZE_NULL_PROGRAMS)

all:                        $(ANALYZE_NULL_PUBLIC)
all:                        $(ANALYZE_NULL_OBJECTS)
all:                        $(ANALYZE_NULL_LIBNAME)
all:                        $(ANALYZE_NULL_PROGRAMS)
build:                      $(ANALYZE_NULL_PUBLIC)
build:                      $(ANALYZE_NULL_OBJECTS)
ci:                         analyze_null_ci
clean:                      analyze_null_clean
clean_public:               analyze_null_clean_public
objects:                    $(ANALYZE_NULL_OBJECTS)
private:                    $(ANALYZE_NULL_PRIVATE)
public:                     $(ANALYZE_NULL_PUBLIC)



#
#    LOCAL UTILITY DEPENDENCIES
#
#    utility dependencies are necessary because of some
#    make-isms having to do with dependencies
#

analyze_null_ci:
	$(CI) $(CIFLAGS) $(ANALYZE_NULL_USED)

analyze_null_clean:
	$(RM) $(RMFLAGS) $(ANALYZE_NULL_OBJECTS) $(ANALYZE_NULL_LIBNAME) $(ANALYZE_NULL_PROGRAMS)

analyze_null_clean_public:
	$(RM) $(RMFLAGS) $(ANALYZE_NULL_PUBLIC)

analyze_null_objects: $(ANALYZE_NULL_OBJECTS)

analyze_null_programs: $(ANALYZE_NULL_PROGRAMS)

analyze_null_public: $(ANALYZE_NULL_PUBLIC)



#
#    BUILD DEPENDENCIES
#
#    build dependencies invoke the rule used to build each
#    class of file
#

$(ANALYZE_NULL_LIBNAME):
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

$(ANALYZE_NULL_OBJECTS):
	$(COMPILE.c) $(ANALYZE_NULL_SRCDIR)$(@:%.o=%.c) $(DEFINES) $(INCLUDES) $(ANALYZE_NULL_LOCALFLAGS)
 
$(ANALYZE_NULL_PUBLIC):
	$(CP) $(CPFLAGS) $(ANALYZE_NULL_SRCDIR)$@ $@

$(ANALYZE_NULL_PROGRAMS):
	$(LINK.c) $@.$(OBJSUFFIX) $(LDLIBS) $(LIBS) $(LIBRARIES) $(LIBPATHS)
#LIBS above is obsolete (use LIBARARIES instead)



#
#    FILE DEPENDENCIES
#
#    file dependencies state, for each file that is built,
#    which file(s) it depends upon
#

null_analyze.$(OBJSUFFIX): $(ANALYZE_NULL_SRCDIR)null_analyze.h
null_analyze.$(OBJSUFFIX): $(ANALYZE_NULL_SRCDIR)null_analyze.c

$(ANALYZE_NULL_LIBNAME): $(ANALYZE_NULL_OBJECTS)
