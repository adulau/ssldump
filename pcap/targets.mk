#
#    targets.mk
#
#



#
#    CONFIGURE USER-DEFINED MAKE ENVIRONMENT
#
#    These fields are specified by the user.  The remainder of
#    this file is generated from this user-specified information.
#
# PCAP_DEFINES:
#    cpp defines, with the -D flag preceeding each
#
# PCAP_INCLUDES:
#    cpp include directories, with the -I flag preceeding each
#
# PCAP_INTERNAL:
#    headers files which are local to a specific module directory,
#    and should not be used by other parts of the toolkit or by
#    the user
#
# PCAP_LIBNAME:
#    the library associated with this module directory, used in
#    most cases for debugging purposes
#
# PCAP_LIBPATHS:
#    link-time directories to search for libraries, with the -L flag
#    preceeding each
#
# PCAP_LIBRARIES:
#    link-time libraries, with the -l flag preceeding each
#
# PCAP_LOCALFLAGS:
#    compile-time flags specific to compiling only the files in
#    this module directory--this variable should only be set in
#    extremely exceptional cases
#
# PCAP_MAKEFILES:
#    the makefiles
#
# PCAP_PREFIX:
#    defines the module name, which also serves as the
#    prefix for all the variable names defined in this file
#
# PCAP_PRIVATE:
#    the private, for-toolkit-use-only API header files
#
# PCAP_NULL_PROGRAMS:
#    programs to build
#
# PCAP_PUBLIC:
#    the header files that define the public API for the toolkit
#    and any other 'public' files that should be copied to
#    the build directory
#
# PCAP_SOURCES:
#    the source files to compile to object
#
PCAP_DEFINES      = -DWITHOUT_MIRROR
PCAP_INCLUDES     = -I$(PCAP_SRCDIR) 
PCAP_INTERNAL     =
PCAP_LIBNAME      =
PCAP_LIBPATHS     =
PCAP_LIBRARIES    =
PCAP_LOCALFLAGS   =
PCAP_MAKEFILES    = targets.mk 
PCAP_PREFIX       = PCAP 
PCAP_PRIVATE      = pcap_logger.h 
PCAP_PROGRAMS     =
PCAP_PUBLIC       =  
PCAP_SOURCES      = sys.c logpkt.c pcap_logger.h 



#
#    CONFIGURE AUTOMATICALLY-GENERATED MAKE ENVIRONMENT
#
# PCAP_OBJECTS:
#    object files to build
#
# PCAP_UNUSED:
#    obsolete files in the module directory that are not
#    used during the build process
#
# PCAP_USED:
#    all files in the module directory that are used
#    during the build process
#
PCAP_OBJECTS      = sys.$(OBJSUFFIX) logpkt.$(OBJSUFFIX) pcap_logger.$(OBJSUFFIX)
PCAP_UNUSED       =
PCAP_USED         = $(PCAP_INTERNAL:%=$(PCAP_SRCDIR)%) \
                            $(PCAP_MAKEFILES:%=$(PCAP_SRCDIR)%) \
                            $(PCAP_PRIVATE:%=$(PCAP_SRCDIR)%) \
                            $(PCAP_PUBLIC:%=$(PCAP_SRCDIR)%) \
                            $(PCAP_SOURCES:%=$(PCAP_SRCDIR)%) 



#
#    NOTES
#
#    The following variables may be used during the build process,
#    but are not defined in this file.  If they are to be set
#    to something other than the default blank, then they must
#    be set by the calling make system.
#
# PCAP_SRCDIR:
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
DEFINES                  += $(PCAP_DEFINES) 
INCLUDES                 += $(PCAP_INCLUDES) 
LIBPATHS                 += $(PCAP_LIBPATHS) 
LIBRARIES                += $(PCAP_LIBRARIES) 
OBJECTS                  += $(PCAP_OBJECTS) 
PUBLIC                   += $(PCAP_PUBLIC) 



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
default:                    $(PCAP_LIBNAME)
default:                    $(PCAP_PROGRAMS)

all:                        $(PCAP_PUBLIC)
all:                        $(PCAP_OBJECTS)
all:                        $(PCAP_LIBNAME)
all:                        $(PCAP_PROGRAMS)
build:                      $(PCAP_PUBLIC)
build:                      $(PCAP_OBJECTS)
ci:                         pcap_ci
clean:                      pcap_clean
clean_public:               pcap_clean_public
objects:                    $(PCAP_OBJECTS)
private:                    $(PCAP_PRIVATE)
public:                     $(PCAP_PUBLIC)



#
#    LOCAL UTILITY DEPENDENCIES
#
#    utility dependencies are necessary because of some
#    make-isms having to do with dependencies
#

pcap_ci:
	$(CI) $(CIFLAGS) $(PCAP_USED)

pcap_clean:
	$(RM) $(RMFLAGS) $(PCAP_OBJECTS) $(PCAP_LIBNAME) $(PCAP_PROGRAMS)

pcap_clean_public:
	$(RM) $(RMFLAGS) $(PCAP_PUBLIC)

pcap_objects: $(PCAP_OBJECTS)

pcap_programs: $(PCAP_PROGRAMS)

pcap_public: $(PCAP_PUBLIC)



#
#    BUILD DEPENDENCIES
#
#    build dependencies invoke the rule used to build each
#    class of file
#

$(PCAP_LIBNAME):
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

$(PCAP_OBJECTS):
	$(COMPILE.c) $(PCAP_SRCDIR)$(@:%.o=%.c) $(DEFINES) $(INCLUDES) $(PCAP_LOCALFLAGS)
 
$(PCAP_PUBLIC):
	$(CP) $(CPFLAGS) $(PCAP_SRCDIR)$@ $@

$(PCAP_PROGRAMS):
	$(LINK.c) $@.$(OBJSUFFIX) $(LDLIBS) $(LIBS) $(LIBRARIES) $(LIBPATHS)
#LIBS above is obsolete (use LIBARARIES instead)



#
#    FILE DEPENDENCIES
#
#    file dependencies state, for each file that is built,
#    which file(s) it depends upon
#

logpkt.$(OBJSUFFIX): $(PCAP_SRCDIR)logpkt.h
logpkt.$(OBJSUFFIX): $(PCAP_SRCDIR)logpkt.c

sys.$(OBJSUFFIX): $(PCAP_SRCDIR)sys.h
sys.$(OBJSUFFIX): $(PCAP_SRCDIR)sys.c

pcap_logger.$(OBJSUFFIX): $(PCAP_SRCDIR)pcap_logger.h
pcap_logger.$(OBJSUFFIX): $(PCAP_SRCDIR)pcap_logger.c

$(PCAP_LIBNAME): $(PCAP_OBJECTS)
