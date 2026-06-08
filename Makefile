CXX ?= g++
CC ?= gcc

BIN_DIR := bin
TARGET := $(BIN_DIR)/stardome-client
SWP_SUBMODULE := third_party/uart_sliding_window_protocol
QCBOR_SUBMODULE := third_party/qcbor
MERKLE_SUBMODULE := third_party/merkle-tree
SCHEMES_SUBMODULE := third_party/stardome-cbor-schemes
XMSS_SUBMODULE := third_party/xmss-reference
BUILD_REQUIRED_SUBMODULES := $(SWP_SUBMODULE) $(QCBOR_SUBMODULE) $(MERKLE_SUBMODULE) $(SCHEMES_SUBMODULE) $(XMSS_SUBMODULE)

INCLUDES := -Iinclude -Isrc -Ithird_party -Ithird_party/uart_sliding_window_protocol -Ithird_party/xmss-reference -Ithird_party/xmss-reference/core -Ithird_party/qcbor/inc -Ithird_party/merkle-tree

CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic -DWITH_CBOR $(INCLUDES)
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -pedantic -DSWP_PLATFORM_EXTENSIONS -DSWP_TIMEOUT_MS=1000 -DQCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS -DQCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS -DWITH_CBOR $(INCLUDES)
LDFLAGS ?=
LDLIBS ?=

CPP_SRCS := \
	src/main.cpp \
	src/cli/options_parser.cpp \
	src/cli/command_router.cpp \
	src/config/app_config.cpp \
	src/config/env_loader.cpp \
	src/commands/command_common.cpp \
	src/commands/cmd_status.cpp \
	src/commands/cmd_host_id.cpp \
	src/commands/cmd_mode.cpp \
	src/commands/cmd_off.cpp \
	src/commands/cmd_proof.cpp \
	src/commands/cmd_attestation.cpp \
	src/commands/cmd_firmware.cpp \
	src/commands/cmd_timestamp.cpp \
	src/commands/cmd_bootlog.cpp \
	src/commands/cmd_verify.cpp \
	src/verify/stardome_attestation_verify.cpp \
	src/transport/serial_port_linux.cpp

C_SRCS := \
	src/transport/swp_client_bridge.c \
	src/verify/xmss_verify_bridge.c \
	third_party/xmss-reference/core/hash_address.c \
	third_party/xmss-reference/core/hash.c \
	third_party/xmss-reference/core/params.c \
	third_party/xmss-reference/core/randombytes.c \
	third_party/xmss-reference/core/sha256.c \
	third_party/xmss-reference/core/utils.c \
	third_party/xmss-reference/core/wots.c \
	third_party/xmss-reference/core/xmss_commons.c \
	third_party/xmss-reference/core/xmss_core.c \
	third_party/xmss-reference/core/xmss_core_hooks.c \
	third_party/xmss-reference/core/xmss.c \
	third_party/uart_sliding_window_protocol/sliding_window_protocol_16bit.c \
	third_party/merkle-tree/merkle_tree.c \
	third_party/merkle-tree/merkle_tree_secure.c \
	third_party/merkle-tree/merkle_tree_cbor.c \
	third_party/merkle-tree/merkle_tree_sha256.c \
	third_party/merkle-tree/merkle_tree_sha256_xmss.c \
	third_party/qcbor/src/UsefulBuf.c \
	third_party/qcbor/src/ieee754.c \
	third_party/qcbor/src/qcbor_decode.c \
	third_party/qcbor/src/qcbor_encode.c \
	third_party/qcbor/src/qcbor_err_to_str.c

OBJS := $(CPP_SRCS:.cpp=.o) $(C_SRCS:.c=.o)

.PHONY: all build clean submodule-update

all: submodule-update
	$(MAKE) SKIP_SUBMODULE_UPDATE=1 build

build: $(TARGET)

submodule-update:
	git submodule update --init --remote $(BUILD_REQUIRED_SUBMODULES)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

ifneq ($(SKIP_SUBMODULE_UPDATE),1)
$(OBJS): | submodule-update
endif

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(TARGET) $(OBJS)
