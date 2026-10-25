ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

APPNAME = "leanVM Verify"
APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

APP_SOURCE_PATH += src
# Keccak-f[1600]: PQ Bench's assembly (ledger-app/src/crypto).
CRYPTO = ../../../ledger-app/src/crypto
APP_SOURCE_FILES += $(CRYPTO)/keccak.c $(CRYPTO)/keccak_thumb2.S
INCLUDES_PATH += $(CRYPTO)
# The verifier, a Rust static library (../build.sh builds it first).
LDLIBS += ../ffi/target/thumbv8m.main-none-eabi/release/libleanvm_ledger_ffi.a
# The verifier's deepest call is ~27.3 KB of stack; the link fails if the app leaves less than this.
APP_STACK_MIN_SIZE = 30000

ICON_NANOSP = icons/leanvm_14px.gif
# Nano home-screen icon, generated from the app icon by the SDK.
ICON_HOME_NANO = glyphs/home_leanvm_14px.gif
ENABLE_NBGL_FOR_NANO_DEVICES = 1

include $(BOLOS_SDK)/Makefile.standard_app
