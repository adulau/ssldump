#
#    local.mk
#
#    $Source: /usr/local/CVS/ssldump/common/lib/local.mk,v $
#    $Revision: 1.2 $
#    $Date: 2001/10/04 17:19:47 $
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
# COMMON_LIB_DEFINES:
#    cpp defines, with the -D flag preceeding each
#
# COMMON_LIB_INCLUDES:
#    cpp include directories, with the -I flag preceeding each
#
# COMMON_LIB_INTERNAL:
#    headers files which are local to a specific module directory,
#    and should not be used by other parts of the toolkit or by
#    the user
#
# COMMON_LIB_LIBNAME:
#    the library associated with this module directory, used in
#    most cases for debugging purposes
#
# COMMON_LIB_LIBPATHS:
#    link-time directories to search for libraries, with the -L flag
#    preceeding each
#
# COMMON_LIB_LIBRARIES:
#    link-time libraries, with the -l flag preceeding each
#
# COMMON_LIB_LOCALFLAGS:
#    compile-time flags specific to compiling only the files in
#    this module directory--this variable should only be set in
#    extremely exceptional cases
#
# COMMON_LIB_MAKEFILES:
#    the makefiles
#
# COMMON_LIB_PREFIX:
#    defines the module name, which also serves as the
#    prefix for all the variable names defined in this file
#
# COMMON_LIB_PRIVATE:
#    the private, for-toolkit-use-only API header files
#
# COMMON_LIB_PROGRAMS:
#    programs to build
#
# COMMON_LIB_PUBLIC:
#    the header files that define the public API for the toolkit
#    and any other 'public' files that should be copied to
#    the build directory
#
# COMMON_LIB_SOURCES:
#    the source files to compile to object
#
COMMON_LIB_DEFINES        =
COMMON_LIB_INCLUDES       =
COMMON_LIB_INTERNAL       =
COMMON_LIB_LIBNAME        =
COMMON_LIB_LIBPATHS       =
COMMON_LIB_LIBRARIES      =
COMMON_LIB_LOCALFLAGS     =
COMMON_LIB_MAKEFILES      = targets.mk 
COMMON_LIB_PREFIX         = COMMON_LIB 
COMMON_LIB_PRIVATE        =
COMMON_LIB_PROGRAMS       =
COMMON_LIB_PUBLIC         =
COMMON_LIB_SOURCES        = debug.c r_assoc.c r_bitfield.c r_data.c \
                            r_errors.c r_list.c r_replace.c r_time.c 



#
#    CONFIGURE AUTOMATICALLY-GENERATED MAKE ENVIRONMENT
#
# COMMON_LIB_OBJECTS:
#    object files to build
#
# COMMON_LIB_UNUSED:
#    obsolete files in the module directory that are not
#    used during the build process
#
# COMMON_LIB_USED:
#    all files in the module directory that are used
#    during the build process
#
COMMON_LIB_OBJECTS        = debug.$(OBJSUFFIX) r_assoc.$(OBJSUFFIX) \
                            r_bitfield.$(OBJSUFFIX) r_data.$(OBJSUFFIX) \
                            r_errors.$(OBJSUFFIX) r_list.$(OBJSUFFIX) \
                            r_replace.$(OBJSUFFIX) r_time.$(OBJSUFFIX) 
COMMON_LIB_UNUSED         = assoc.h debug.h local.mk r_assoc_test.c r_data.h 
COMMON_LIB_USED           = $(COMMON_LIB_INTERNAL:%=$(COMMON_LIB_SRCDIR)%) \
                            $(COMMON_LIB_MAKEFILES:%=$(COMMON_LIB_SRCDIR)%) \
                            $(COMMON_LIB_PRIVATE:%=$(COMMON_LIB_SRCDIR)%) \
                            $(COMMON_LIB_PUBLIC:%=$(COMMON_LIB_SRCDIR)%) \
                            $(COMMON_LIB_SOURCES:%=$(COMMON_LIB_SRCDIR)%) 



#
#    NOTES
#
#    The following variables may be used during the build process,
#    but are not defined in this file.  If they are to be set
#    to something other than the default blank, then they must
#    be set by the calling make system.
#
# COMMON_LIB_SRCDIR:
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
DEFINES                  += $(COMMON_LIB_DEFINES) 
INCLUDES                 += $(COMMON_LIB_INCLUDES) 
LIBPATHS                 += $(COMMON_LIB_LIBPATHS) 
LIBRARIES                += $(COMMON_LIB_LIBRARIES) 
OBJECTS                  += $(COMMON_LIB_OBJECTS) 
PUBLIC                   += $(COMMON_LIB_PUBLIC) 



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
default:                    $(COMMON_LIB_LIBNAME)
default:                    $(COMMON_LIB_PROGRAMS)

all:                        $(COMMON_LIB_PUBLIC)
all:                        $(COMMON_LIB_OBJECTS)
all:                        $(COMMON_LIB_LIBNAME)
all:                        $(COMMON_LIB_PROGRAMS)
build:                      $(COMMON_LIB_PUBLIC)
build:                      $(COMMON_LIB_OBJECTS)
ci:                         common_lib_ci
clean:                      common_lib_clean
clean_public:               common_lib_clean_public
objects:                    $(COMMON_LIB_OBJECTS)
private:                    $(COMMON_LIB_PRIVATE)
public:                     $(COMMON_LIB_PUBLIC)



#
#    LOCAL UTILITY DEPENDENCIES
#
#    utility dependencies are necessary because of some
#    make-isms having to do with dependencies
#

common_lib_ci:
	$(CI) $(CIFLAGS) $(COMMON_LIB_USED)

common_lib_clean:
	$(RM) $(RMFLAGS) $(COMMON_LIB_OBJECTS) $(COMMON_LIB_LIBNAME) $(COMMON_LIB_PROGRAMS)

common_lib_clean_public:
	$(RM) $(RMFLAGS) $(COMMON_LIB_PUBLIC)

common_lib_objects: $(COMMON_LIB_OBJECTS)

common_lib_programs: $(COMMON_LIB_PROGRAMS)

common_lib_public: $(COMMON_LIB_PUBLIC)



#
#    BUILD DEPENDENCIES
#
#    build dependencies invoke the rule used to build each
#    class of file
#

$(COMMON_LIB_LIBNAME):
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

$(COMMON_LIB_OBJECTS):
	$(COMPILE.c) $(COMMON_LIB_SRCDIR)$(@:%.$(OBJSUFFIX)=%.c) $(DEFINES) $(INCLUDES) $(COMMON_LIB_LOCALFLAGS)
 
$(COMMON_LIB_PUBLIC):
	$(CP) $(CPFLAGS) $(COMMON_LIB_SRCDIR)$@ $@

$(COMMON_LIB_PROGRAMS):
	$(LINK.c) $@.$(OBJSUFFIX) $(LDLIBS) $(LIBS) $(LIBRARIES) $(LIBPATHS)
#LIBS above is obsolete (use LIBARARIES instead)



#
#    FILE DEPENDENCIES
#
#    file dependencies state, for each file that is built,
#    which file(s) it depends upon
#

debug.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)debug.h
debug.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)debug.c

r_assoc.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)r_assoc.c

r_bitfield.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)r_bitfield.c

r_data.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)r_data.h
r_data.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)r_data.c

r_errors.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)r_errors.c

r_list.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)r_list.c

r_replace.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)r_replace.c

r_time.$(OBJSUFFIX): $(COMMON_LIB_SRCDIR)r_time.c

$(COMMON_LIB_LIBNAME): $(COMMON_LIB_OBJECTS)
