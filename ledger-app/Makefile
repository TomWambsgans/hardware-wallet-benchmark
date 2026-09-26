ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

APPNAME = "PQ Bench"
APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

APP_SOURCE_PATH += src

ICON_NANOSP = icons/pqbench_14px.gif
# Nano home-screen icon, generated from the app icon by the SDK.
ICON_HOME_NANO = glyphs/home_pqbench_14px.gif
ENABLE_NBGL_FOR_NANO_DEVICES = 1

include $(BOLOS_SDK)/Makefile.standard_app

# The SDK builds apps at -Oz; the crypto (src/crypto) at -O3. App objects live under
# $(OBJ_DIR)/app/<path from the git root>/.
CRYPTO_OBJ_DIR = $(OBJ_DIR)/app/$(patsubst $(APP_DIR)/%,%,$(CURDIR))/src/crypto
$(CRYPTO_OBJ_DIR)/%.o: CFLAGS += -O3
