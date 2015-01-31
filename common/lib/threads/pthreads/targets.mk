#
#    targets.mk
#
#    $Source: /usr/local/CVS/ssldump/common/lib/threads/pthreads/targets.mk,v $
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
# THREADS_PTHREADS_DEFINES:
#    cpp defines, with the -D flag preceeding each
#
# THREADS_PTHREADS_INCLUDES:
#    cpp include directories, with the -I flag preceeding each
#
# THREADS_PTHREADS_INTERNAL:
#    headers files which are local to a specific module directory,
#    and should not be used by other parts of the toolkit or by
#    the user
#
# THREADS_PTHREADS_LIBNAME:
#    the library associated with this module directory, used in
#    most cases for debugging purposes
#
# THREADS_PTHREADS_LIBPATHS:
#    link-time directories to search for libraries, with the -L flag
#    preceeding each
#
# THREADS_PTHREADS_LIBRARIES:
#    link-time libraries, with the -l flag preceeding each
#
# THREADS_PTHREADS_LOCALFLAGS:
#    compile-time flags specific to compiling only the files in
#    this module directory--this variable should only be set in
#    extremely exceptional cases
#
# THREADS_PTHREADS_MAKEFILES:
#    the makefiles
#
# THREADS_PTHREADS_PREFIX:
#    defines the module name, which also serves as the
#    prefix for all the variable names defined in this file
#
# THREADS_PTHREADS_PRIVATE:
#    the private, for-toolkit-use-only API header files
#
# THREADS_PTHREADS_PROGRAMS:
#    programs to build
#
# THREADS_PTHREADS_PUBLIC:
#    the header files that define the public API for the toolkit
#    and any other 'public' files that should be copied to
#    the build directory
#
# THREADS_PTHREADS_SOURCES:
#    the source files to compile to object
#
THREADS_PTHREADS_DEFINES  =
THREADS_PTHREADS_INCLUDES  =
THREADS_PTHREADS_INTERNAL  =
THREADS_PTHREADS_LIBNAME  =
THREADS_PTHREADS_LIBPATHS  =
THREADS_PTHREADS_LIBRARIES  =
THREADS_PTHREADS_LOCALFLAGS  =
THREADS_PTHREADS_MAKEFILES  =
THREADS_PTHREADS_PREFIX   = THREADS_PTHREADS 
THREADS_PTHREADS_PRIVATE  =
THREADS_PTHREADS_PROGRAMS  =
THREADS_PTHREADS_PUBLIC   =
THREADS_PTHREADS_SOURCES  = pthread.c 



#
#    CONFIGURE AUTOMATICALLY-GENERATED MAKE ENVIRONMENT
#
# THREADS_PTHREADS_OBJECTS:
#    object files to build
#
# THREADS_PTHREADS_UNUSED:
#    obsolete files in the module directory that are not
#    used during the build process
#
# THREADS_PTHREADS_USED:
#    all files in the module directory that are used
#    during the build process
#
THREADS_PTHREADS_OBJECTS  = pthread.$(OBJSUFFIX) 
THREADS_PTHREADS_UNUSED   = targets.mk 
THREADS_PTHREADS_USED     = $(THREADS_PTHREADS_INTERNAL:%=$(THREADS_PTHREADS_SRCDIR)%) \
                            $(THREADS_PTHREADS_MAKEFILES:%=$(THREADS_PTHREADS_SRCDIR)%) \
                            $(THREADS_PTHREADS_PRIVATE:%=$(THREADS_PTHREADS_SRCDIR)%) \
                            $(THREADS_PTHREADS_PUBLIC:%=$(THREADS_PTHREADS_SRCDIR)%) \
                            $(THREADS_PTHREADS_SOURCES:%=$(THREADS_PTHREADS_SRCDIR)%) 



#
#    NOTES
#
#    The following variables may be used during the build process,
#    but are not defined in this file.  If they are to be set
#    to something other than the default blank, then they must
#    be set by the calling make system.
#
# THREADS_PTHREADS_SRCDIR:
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
DEFINES                  += $(THREADS_PTHREADS_DEFINES) 
INCLUDES                 += $(THREADS_PTHREADS_INCLUDES) 
LIBPATHS                 += $(THREADS_PTHREADS_LIBPATHS) 
LIBRARIES                += $(THREADS_PTHREADS_LIBRARIES) 
OBJECTS                  += $(THREADS_PTHREADS_OBJECTS) 
PUBLIC                   += $(THREADS_PTHREADS_PUBLIC) 



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
default:                    $(THREADS_PTHREADS_LIBNAME)
default:                    $(THREADS_PTHREADS_PROGRAMS)

all:                        $(THREADS_PTHREADS_PUBLIC)
all:                        $(THREADS_PTHREADS_OBJECTS)
all:                        $(THREADS_PTHREADS_LIBNAME)
all:                        $(THREADS_PTHREADS_PROGRAMS)
build:                      $(THREADS_PTHREADS_PUBLIC)
build:                      $(THREADS_PTHREADS_OBJECTS)
ci:                         threads_pthreads_ci
clean:                      threads_pthreads_clean
clean_public:               threads_pthreads_clean_public
objects:                    $(THREADS_PTHREADS_OBJECTS)
private:                    $(THREADS_PTHREADS_PRIVATE)
public:                     $(THREADS_PTHREADS_PUBLIC)



#
#    LOCAL UTILITY DEPENDENCIES
#
#    utility dependencies are necessary because of some
#    make-isms having to do with dependencies
#

threads_pthreads_ci:
	$(CI) $(CIFLAGS) $(THREADS_PTHREADS_USED)

threads_pthreads_clean:
	$(RM) $(RMFLAGS) $(THREADS_PTHREADS_OBJECTS) $(THREADS_PTHREADS_LIBNAME) $(THREADS_PTHREADS_PROGRAMS)

threads_pthreads_clean_public:
	$(RM) $(RMFLAGS) $(THREADS_PTHREADS_PUBLIC)

threads_pthreads_objects: $(THREADS_PTHREADS_OBJECTS)

threads_pthreads_programs: $(THREADS_PTHREADS_PROGRAMS)

threads_pthreads_public: $(THREADS_PTHREADS_PUBLIC)



#
#    BUILD DEPENDENCIES
#
#    build dependencies invoke the rule used to build each
#    class of file
#

$(THREADS_PTHREADS_LIBNAME):
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

$(THREADS_PTHREADS_OBJECTS):
	$(COMPILE.c) $(THREADS_PTHREADS_SRCDIR)$(@:%.$(OBJSUFFIX)=%.c) $(DEFINES) $(INCLUDES) $(THREADS_PTHREADS_LOCALFLAGS)
 
$(THREADS_PTHREADS_PUBLIC):
	$(CP) $(CPFLAGS) $(THREADS_PTHREADS_SRCDIR)$@ $@

$(THREADS_PTHREADS_PROGRAMS):
	$(LINK.c) $@.$(OBJSUFFIX) $(LDLIBS) $(LIBS) $(LIBRARIES) $(LIBPATHS)
#LIBS above is obsolete (use LIBARARIES instead)



#
#    FILE DEPENDENCIES
#
#    file dependencies state, for each file that is built,
#    which file(s) it depends upon
#

pthread.$(OBJSUFFIX): $(THREADS_PTHREADS_SRCDIR)pthread.c

$(THREADS_PTHREADS_LIBNAME): $(THREADS_PTHREADS_OBJECTS)
