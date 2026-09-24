ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

APPNAME = "PQ Bench"

APPVERSION_M = 0
APPVERSION_N = 1
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

APP_SOURCE_PATH += src

ICON_NANOSP = icons/pqbench_14px.gif
ICON_NANOX = icons/pqbench_14px.gif
# Nano NBGL home screen icon, generated from the app icon by the SDK.
ICON_HOME_NANO = glyphs/home_pqbench_14px.gif

ENABLE_NBGL_FOR_NANO_DEVICES = 1

# Optimization level of the crypto sources (src/crypto). The SDK builds
# everything else, as it does every app by default, at -Oz.
CRYPTO_OPT ?= 3
DEFINES += CRYPTO_OPT_LEVEL=\"$(CRYPTO_OPT)\"

include $(BOLOS_SDK)/Makefile.standard_app

# App objects live under $(OBJ_DIR)/app/<path from the git root>/.
CRYPTO_OBJ_DIR = $(OBJ_DIR)/app/$(patsubst $(APP_DIR)/%,%,$(CURDIR))/src/crypto
$(CRYPTO_OBJ_DIR)/%.o: CFLAGS += -O$(CRYPTO_OPT)
