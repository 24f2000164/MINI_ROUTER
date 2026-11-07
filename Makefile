# Makefile - Mini Router: L2/L3 Packet Forwarding and ACL Engine
# Target platform: Linux (GCC / Clang, C99)
#
# Targets:
#   make all       - Build the main router binary (minirouter)
#   make test      - Build and run all unit tests
#   make test_lpm  - Build and run LPM unit tests only
#   make test_acl  - Build and run ACL unit tests only
#   make test_fwd  - Build and run forwarding simulation tests only
#   make test_csum - Build and run checksum unit tests only
#   make clean     - Remove build artifacts

CC      ?= gcc
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -Wshadow \
           -Wstrict-prototypes -Wmissing-prototypes \
           -g -O2 -Iinclude
LDFLAGS :=

# Source files for the main router (TAP mode, requires Linux + root)
ROUTER_SRCS := \
    src/main.c       \
    src/router.c     \
    src/ethernet.c   \
    src/ipv4.c       \
    src/arp.c        \
    src/icmp.c       \
    src/routing.c    \
    src/acl.c        \
    src/stats.c      \
    src/netdev_tap.c

# Source files shared by all unit tests (use mock device driver)
COMMON_TEST_SRCS := \
    src/ethernet.c   \
    src/ipv4.c       \
    src/routing.c    \
    src/acl.c        \
    src/stats.c      \
    src/netdev_mock.c

# Forwarding test additionally needs arp, icmp, router dispatch
FWD_TEST_SRCS := \
    $(COMMON_TEST_SRCS) \
    src/arp.c        \
    src/icmp.c       \
    src/router.c

BUILD_DIR := build

# ── Default target: build the router ────────────────────────────────────────
.PHONY: all
all: $(BUILD_DIR)/minirouter

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/minirouter: $(ROUTER_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: $@"

# ── Unit Tests ───────────────────────────────────────────────────────────────
.PHONY: test test_lpm test_acl test_fwd test_csum

test: test_lpm test_acl test_fwd test_csum

test_lpm: $(BUILD_DIR)/test_lpm
	@echo ""
	@echo "--- Running LPM Tests ---"
	./$<

test_acl: $(BUILD_DIR)/test_acl
	@echo ""
	@echo "--- Running ACL Tests ---"
	./$<

test_fwd: $(BUILD_DIR)/test_fwd
	@echo ""
	@echo "--- Running Forwarding Tests ---"
	./$<

test_csum: $(BUILD_DIR)/test_csum
	@echo ""
	@echo "--- Running Checksum Tests ---"
	./$<

$(BUILD_DIR)/test_lpm: tests/test_lpm.c $(COMMON_TEST_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/test_acl: tests/test_acl.c $(COMMON_TEST_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/test_fwd: tests/test_forwarding.c $(FWD_TEST_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/test_csum: tests/test_checksum.c src/ipv4.c src/ethernet.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ── Clean ────────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"
