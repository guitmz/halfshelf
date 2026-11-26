CC := gcc
FASM := fasm
LOADER := halfshelf
HLOADER := headshelf

# Everything generated lives under the repo, never in a shared /tmp where
# another local user could plant files or symlinks with the same names
BUILD := build
STRIP := $(BUILD)/strip_headers

TEST_DIR := tests
SHELF_TEST := $(BUILD)/halfshelf_test
SHELF_TLS_ARGV := $(BUILD)/halfshelf_tls_argv
SHELF_NOLIBC := $(BUILD)/halfshelf_nolibc

COMMON_CFLAGS := -Wall -Wextra -fno-asynchronous-unwind-tables -fno-unwind-tables
SHELF_LDFLAGS := -static-pie -Wl,--no-eh-frame-hdr -Wl,-T,$(TEST_DIR)/static-pie.ld
NOLIBC_CFLAGS := -fPIE -ffreestanding -fno-stack-protector -nostdlib

LOADER_INCS := utils.inc loader/reloc.inc loader/stack.inc loader/common.inc loader/rwdata.inc loader/rodata.inc

.PHONY: all clean inspect run corrupt-tests

define run_expect
	@./$(LOADER) $(1); \
	status=$$?; \
	if [ $$status -ne $(2) ]; then \
		echo "FAIL: ./$(LOADER) $(1) exited $$status, expected $(2)"; \
		exit $$status; \
	fi
endef

define run_headless_expect
	@./$(HLOADER) $(1) $(2) $(3); \
	status=$$?; \
	if [ $$status -ne $(4) ]; then \
		echo "FAIL: ./$(HLOADER) $(1) $(2) $(3) exited $$status, expected $(4)"; \
		exit $$status; \
	fi
endef

define run_memfd_expect
	@cat $(1) | ./$(HLOADER) --memfd $(2) $(3); \
	status=$$?; \
	if [ $$status -ne $(4) ]; then \
		echo "FAIL: cat $(1) | ./$(HLOADER) --memfd $(2) $(3) exited $$status, expected $(4)"; \
		exit $$status; \
	fi
endef

all: $(LOADER) $(HLOADER) $(STRIP)

$(BUILD):
	mkdir -p $@

$(LOADER): halfshelf.asm loader/validate.inc $(LOADER_INCS)
	$(FASM) halfshelf.asm
	chmod +x $(LOADER)

$(HLOADER): headshelf.asm $(LOADER_INCS)
	$(FASM) headshelf.asm
	chmod +x $(HLOADER)

$(STRIP): strip_headers/strip_headers.asm utils.inc | $(BUILD)
	$(FASM) strip_headers/strip_headers.asm $@
	chmod +x $@

$(SHELF_TEST): $(TEST_DIR)/test.c $(TEST_DIR)/static-pie.ld | $(BUILD)
	$(CC) $(COMMON_CFLAGS) $(SHELF_LDFLAGS) -o $@ $<

$(SHELF_TLS_ARGV): $(TEST_DIR)/test_argv_tls.c $(TEST_DIR)/static-pie.ld | $(BUILD)
	$(CC) $(COMMON_CFLAGS) $(SHELF_LDFLAGS) -o $@ $<

$(SHELF_NOLIBC): $(TEST_DIR)/test_nolibc.c $(TEST_DIR)/static-pie.ld | $(BUILD)
	$(CC) $(COMMON_CFLAGS) $(NOLIBC_CFLAGS) $(SHELF_LDFLAGS) -o $@ $<

# Both metadata formats come with the same stripped payload next to them
$(BUILD)/%.meta: $(BUILD)/% $(STRIP)
	$(STRIP) $< $(BUILD)/$*.payload $@

$(BUILD)/%.binmeta: $(BUILD)/% $(STRIP)
	$(STRIP) --headless-bin $< $(BUILD)/$*.payload $@

inspect: $(SHELF_TEST) $(SHELF_TLS_ARGV) $(SHELF_NOLIBC)
	for f in $^; do \
		file $$f; readelf -h $$f; readelf -l $$f; readelf -d $$f || true; echo; \
	done

run: all $(SHELF_TEST).meta $(SHELF_TLS_ARGV).meta $(SHELF_TEST).binmeta $(SHELF_TLS_ARGV).binmeta $(SHELF_NOLIBC).binmeta
	$(call run_expect,$(SHELF_TEST),7)
	$(call run_expect,$(SHELF_TLS_ARGV) alpha beta,7)
	$(call run_expect,$(SHELF_NOLIBC),7)
	$(call run_headless_expect,$(SHELF_TEST).payload,$(SHELF_TEST).meta,,7)
	$(call run_headless_expect,$(SHELF_TLS_ARGV).payload,$(SHELF_TLS_ARGV).meta,alpha beta,7)
	$(call run_headless_expect,$(SHELF_TEST).payload,$(SHELF_TEST).binmeta,,7)
	$(call run_headless_expect,$(SHELF_TLS_ARGV).payload,$(SHELF_TLS_ARGV).binmeta,alpha beta,7)
	$(call run_headless_expect,$(SHELF_NOLIBC).payload,$(SHELF_NOLIBC).binmeta,,7)
	$(call run_memfd_expect,$(SHELF_TEST).payload,$(SHELF_TEST).binmeta,,7)
	$(call run_memfd_expect,$(SHELF_TLS_ARGV).payload,$(SHELF_TLS_ARGV).binmeta,alpha beta,7)

# Each case must be refused with exit status 1. A crash exits with a signal
# status instead, so it fails the check rather than passing as a refusal
define expect_refused
	@$(1) >$(BUILD)/corrupt.out 2>$(BUILD)/corrupt.err; \
	status=$$?; \
	if [ $$status -ne 1 ]; then \
		echo "FAIL $(1) exited $$status, expected a clean refusal with status 1"; \
		exit 1; \
	fi
endef

corrupt-tests: all $(SHELF_TEST) $(SHELF_TEST).meta $(SHELF_TEST).binmeta
	@cp $(SHELF_TEST).binmeta $(BUILD)/bad_truncated
	@truncate -s -1 $(BUILD)/bad_truncated
	$(call expect_refused,./$(HLOADER) $(SHELF_TEST).payload $(BUILD)/bad_truncated)
	@cp $(SHELF_TEST).binmeta $(BUILD)/bad_magic
	@printf 'X' | dd of=$(BUILD)/bad_magic bs=1 seek=0 conv=notrunc 2>/dev/null
	$(call expect_refused,./$(HLOADER) $(SHELF_TEST).payload $(BUILD)/bad_magic)
	@cp $(SHELF_TEST).binmeta $(BUILD)/bad_trailing
	@printf 'X' >> $(BUILD)/bad_trailing
	$(call expect_refused,./$(HLOADER) $(SHELF_TEST).payload $(BUILD)/bad_trailing)
	@cp $(SHELF_TEST).binmeta $(BUILD)/bad_memsz
	@printf '\000\000\000\000\000\000\000\000' | dd of=$(BUILD)/bad_memsz bs=1 seek=72 conv=notrunc 2>/dev/null
	$(call expect_refused,./$(HLOADER) $(SHELF_TEST).payload $(BUILD)/bad_memsz)
	@head -c -1 $(SHELF_TEST).meta > $(BUILD)/bad_long_phdr_hex
	@printf '%08192d\n' 0 >> $(BUILD)/bad_long_phdr_hex
	$(call expect_refused,./$(HLOADER) $(SHELF_TEST).payload $(BUILD)/bad_long_phdr_hex)
	@cp $(SHELF_TEST) $(BUILD)/bad_phoff
	@printf '\000\000\000\020\000\000\000\000' | dd of=$(BUILD)/bad_phoff bs=1 seek=32 conv=notrunc 2>/dev/null
	$(call expect_refused,./$(LOADER) $(BUILD)/bad_phoff)
	@truncate -s 1048577 $(BUILD)/too_large
	$(call expect_refused,./$(LOADER) $(BUILD)/too_large)
	@echo "halfshelf corrupt tests: ok"

clean:
	rm -f $(LOADER) $(HLOADER)
	rm -rf $(BUILD)
