PACKAGE = fenix-firewall
VERSION = 1.0
NATIVE = yes
CVSBUILD = no
DEBUG = no
INSTALL = install
STRIP = strip
PREFIX = /usr/local
DESTDIR = $(HOME)/fenix-firewall
DEBIAN = $(HOME)
MACHINE = other

LINGUAS = 

ifeq ($(MACHINE),ipaq)
PACKAGE_CPPFLAGS += -DMACH_IPAQ
PACKAGE_CFLAGS += -DMACH_IPAQ
endif

ifeq ($(MACHINE),simpad)
PACKAGE_CPPFLAGS += -DMACH_SIMPAD
PACKAGE_CFLAGS += -DMACH_SIMPAD
endif

EXTRA_DESKTOPS = fenix-firewall.desktop.in 
HELPFILE = fenix-firewall.html

GTKCFLAGS = `pkg-config --cflags gtk+-2.0 gdk-2.0`
GTKLDFLAGS = `pkg-config --libs gtk+-2.0 gdk-2.0`

ifeq ($(CVSBUILD),yes)
PACKAGE_LDFLAGS += -L../libgpewidget -L.
PACKAGE_CFLAGS += -I../libgpewidget -I.
BUILD = ../build
else
BUILD = build
endif

PACKAGE_CPPFLAGS = $(STANDARD_CPPFLAGS)
PACKAGE_CFLAGS += $(STANDARD_CFLAGS) $(GTKCFLAGS) $(GPECFLAGS)
PACKAGE_LDFLAGS += $(STANDARD_LDFLAGS) $(GPELIBS) $(GTKLDFLAGS)


MEMBERS  = main interface backend editrule

ifeq ($(DEBUG),yes)
PACKAGE_CFLAGS += -g -DDEBUG
else
PACKAGE_CFLAGS += -Os -fomit-frame-pointer
endif

PACKAGE_CFLAGS += -DVERSION=\"$(VERSION)\" -DPREFIX=\"$(PREFIX)\" -D_GNU_SOURCE
PACKAGE_CFLAGS += -DPACKAGE=\"$(PACKAGE)\" -DPACKAGE_LOCALE_DIR=\"$(PREFIX)/share/locale\"

OBJS = $(patsubst %,%.o,$(MEMBERS))
DEPS = $(patsubst %,%.d,$(MEMBERS))
SOURCES = $(patsubst %,%.c,$(MEMBERS))


PIXMAPS = fenix-firewall.png exit.png

all: $(PACKAGE) 

$(PACKAGE): $(OBJS)
	$(CC) -g -o $@ $(OBJS) $(LDFLAGS) $(PACKAGE_LDFLAGS)

install-program: $(PACKAGE) all-desktop
	mkdir -p $(DESTDIR)/DEBIAN
	sed -e s/VERSION/$(VERSION)/ < familiar/control > $(DESTDIR)/DEBIAN/control
	mkdir -p $(DESTDIR)/etc/fenix
#	touch $(DESTDIR)/etc/fenix/fenix-firewall-load
	mkdir -p $(DESTDIR)/$(PREFIX)/bin
	mkdir -p $(DESTDIR)/etc/init.d/
	$(INSTALL) -m 4755 $(PACKAGE) $(DESTDIR)$(PREFIX)/bin/$(PACKAGE)
	$(STRIP) $(DESTDIR)$(PREFIX)/bin/$(PACKAGE)
	$(INSTALL) -m 755 fenix-daemon $(DESTDIR)/etc/init.d/
	mkdir -p $(DESTDIR)$(PREFIX)/usr/share/pixmaps
	mkdir -p $(DESTDIR)/share/pixmaps
	for i in $(PIXMAPS); do install -m 644 -D pixmaps/$$i $(DESTDIR)$(PREFIX)/share/pixmaps/$$i; \
	install -m 644 -D pixmaps/$$i $(DESTDIR)/usr/share/pixmaps/$$i; done
	mkdir -p $(DESTDIR)$(PREFIX)/share/applications
	$(INSTALL) -m 644 *.desktop $(DESTDIR)$(PREFIX)/share/applications
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/fenix
	$(INSTALL) -m 644 $(HELPFILE) $(DESTDIR)$(PREFIX)/share/doc/fenix/
	rm -rf $(DEBIAN)/*.deb
	dpkg-deb -b $(DESTDIR) $(DEBIAN)
	echo === A instalacao requer root ====
	sudo dpkg -i $(DEBIAN)/fenix*.deb
	rm -rf $(DESTDIR)/


clean:
	rm -f $(PACKAGE) $(OBJS) *~ */*~ *.ipk *.o
	rm -f $(DEBIAN)/fenix*.deb

include $(BUILD)/Makefile.dpkg_ipkg
include $(BUILD)/Makefile.translation
