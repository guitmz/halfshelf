CC := gcc
FASM := fasm
LOADER := halfshelf
HLOADER := headshelf
META_FORMAT ?= text

TEST_DIR := tests
SHELF_TEST := /tmp/halfshelf_test
SHELF_TLS_ARGV := /tmp/halfshelf_tls_argv
SHELF_HEADLESS_PAYLOAD := /tmp/halfshelf_test.payload
SHELF_HEADLESS_META := /tmp/halfshelf_test.meta
SHELF_HEADLESS_META_BIN := /tmp/halfshelf_test.binmeta
SHELF_TLS_ARGV_PAYLOAD := /tmp/halfshelf_tls_argv.payload
SHELF_TLS_ARGV_META := /tmp/halfshelf_tls_argv.meta
SHELF_TLS_ARGV_META_BIN := /tmp/halfshelf_tls_argv.binmeta

COMMON_CFLAGS := -Wall -Wextra -fno-asynchronous-unwind-tables -fno-unwind-tables
SHELF_LDFLAGS := -static-pie -Wl,--no-eh-frame-hdr -Wl,-T,$(TEST_DIR)/static-pie.ld

.PHONY: all clean inspect run corrupt-tests meta meta-tool FORCE

FORCE:

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

all: $(LOADER) $(HLOADER)

$(LOADER): halfshelf.asm utils.inc loader/validate.inc loader/reloc.inc loader/stack.inc loader/rwdata.inc loader/rodata.inc
	$(FASM) halfshelf.asm
	chmod +x $(LOADER)

$(HLOADER): headshelf.asm utils.inc loader/reloc.inc loader/stack.inc loader/rwdata.inc loader/rodata.inc
	$(FASM) headshelf.asm
	chmod +x $(HLOADER)

$(SHELF_TEST): $(TEST_DIR)/test.c $(TEST_DIR)/static-pie.ld
	$(CC) $(COMMON_CFLAGS) $(SHELF_LDFLAGS) -o $@ $(TEST_DIR)/test.c

$(SHELF_TLS_ARGV): $(TEST_DIR)/test_argv_tls.c $(TEST_DIR)/static-pie.ld
	$(CC) $(COMMON_CFLAGS) $(SHELF_LDFLAGS) -o $@ $(TEST_DIR)/test_argv_tls.c

meta-tool: strip_headers/strip_headers.asm utils.inc
	$(FASM) strip_headers/strip_headers.asm /tmp/strip_headers
	chmod +x /tmp/strip_headers

$(SHELF_HEADLESS_META): FORCE meta-tool $(SHELF_TEST)
	/tmp/strip_headers $(SHELF_TEST) $(SHELF_HEADLESS_PAYLOAD) $(SHELF_HEADLESS_META)
$(SHELF_TLS_ARGV_META): FORCE meta-tool $(SHELF_TLS_ARGV)
	/tmp/strip_headers $(SHELF_TLS_ARGV) $(SHELF_TLS_ARGV_PAYLOAD) $(SHELF_TLS_ARGV_META)
$(SHELF_HEADLESS_META_BIN): FORCE meta-tool $(SHELF_TEST)
	/tmp/strip_headers --headless-bin $(SHELF_TEST) $(SHELF_HEADLESS_PAYLOAD) $(SHELF_HEADLESS_META_BIN)
$(SHELF_TLS_ARGV_META_BIN): FORCE meta-tool $(SHELF_TLS_ARGV)
	/tmp/strip_headers --headless-bin $(SHELF_TLS_ARGV) $(SHELF_TLS_ARGV_PAYLOAD) $(SHELF_TLS_ARGV_META_BIN)

ifeq ($(META_FORMAT),bin)
meta: $(SHELF_HEADLESS_META_BIN) $(SHELF_TLS_ARGV_META_BIN)
else
meta: $(SHELF_HEADLESS_META) $(SHELF_TLS_ARGV_META)
endif

inspect: $(SHELF_TEST) $(SHELF_TLS_ARGV)
	file $(SHELF_TEST)
	readelf -h $(SHELF_TEST)
	readelf -l $(SHELF_TEST)
	readelf -d $(SHELF_TEST) || true
	echo
	file $(SHELF_TLS_ARGV)
	readelf -h $(SHELF_TLS_ARGV)
	readelf -l $(SHELF_TLS_ARGV)
	readelf -d $(SHELF_TLS_ARGV) || true

run: $(LOADER) $(HLOADER) $(SHELF_TEST) $(SHELF_TLS_ARGV) $(SHELF_HEADLESS_META) $(SHELF_TLS_ARGV_META) $(SHELF_HEADLESS_META_BIN) $(SHELF_TLS_ARGV_META_BIN)
	chmod +x $(LOADER) $(HLOADER)
	$(call run_expect,$(SHELF_TEST),7)
	$(call run_expect,$(SHELF_TLS_ARGV) alpha beta,7)
	$(call run_headless_expect,$(SHELF_HEADLESS_PAYLOAD),$(SHELF_HEADLESS_META),,7)
	$(call run_headless_expect,$(SHELF_TLS_ARGV_PAYLOAD),$(SHELF_TLS_ARGV_META),alpha beta,7)
	$(call run_headless_expect,$(SHELF_HEADLESS_PAYLOAD),$(SHELF_HEADLESS_META_BIN),,7)
	$(call run_headless_expect,$(SHELF_TLS_ARGV_PAYLOAD),$(SHELF_TLS_ARGV_META_BIN),alpha beta,7)
	$(call run_memfd_expect,$(SHELF_HEADLESS_PAYLOAD),$(SHELF_HEADLESS_META_BIN),,7)
	$(call run_memfd_expect,$(SHELF_TLS_ARGV_PAYLOAD),$(SHELF_TLS_ARGV_META_BIN),alpha beta,7)

corrupt-tests: $(LOADER) $(HLOADER) $(SHELF_TEST) $(SHELF_HEADLESS_META_BIN)
	@cp $(SHELF_HEADLESS_META_BIN) /tmp/halfshelf_bad_truncated
	@truncate -s -1 /tmp/halfshelf_bad_truncated
	@! ./$(HLOADER) $(SHELF_HEADLESS_PAYLOAD) /tmp/halfshelf_bad_truncated >/tmp/halfshelf.corrupt.out 2>/tmp/halfshelf.corrupt.err
	@cp $(SHELF_HEADLESS_META_BIN) /tmp/halfshelf_bad_magic
	@printf 'X' | dd of=/tmp/halfshelf_bad_magic bs=1 seek=0 conv=notrunc 2>/dev/null
	@! ./$(HLOADER) $(SHELF_HEADLESS_PAYLOAD) /tmp/halfshelf_bad_magic >/tmp/halfshelf.corrupt.out 2>/tmp/halfshelf.corrupt.err
	@cp $(SHELF_HEADLESS_META_BIN) /tmp/halfshelf_bad_trailing
	@printf 'X' >> /tmp/halfshelf_bad_trailing
	@! ./$(HLOADER) $(SHELF_HEADLESS_PAYLOAD) /tmp/halfshelf_bad_trailing >/tmp/halfshelf.corrupt.out 2>/tmp/halfshelf.corrupt.err
	@cp $(SHELF_HEADLESS_META_BIN) /tmp/halfshelf_bad_memsz
	@printf '\000\000\000\000\000\000\000\000' | dd of=/tmp/halfshelf_bad_memsz bs=1 seek=72 conv=notrunc 2>/dev/null
	@! ./$(HLOADER) $(SHELF_HEADLESS_PAYLOAD) /tmp/halfshelf_bad_memsz >/tmp/halfshelf.corrupt.out 2>/tmp/halfshelf.corrupt.err
	@truncate -s 1048577 /tmp/halfshelf_too_large
	@! ./$(LOADER) /tmp/halfshelf_too_large >/tmp/halfshelf.corrupt.out 2>/tmp/halfshelf.corrupt.err
	@echo "halfshelf corrupt tests: ok"

clean:
	rm -f $(LOADER) $(HLOADER) \
		$(SHELF_TEST) \
		$(SHELF_TLS_ARGV) \
		$(SHELF_HEADLESS_PAYLOAD) $(SHELF_HEADLESS_META) $(SHELF_HEADLESS_META_BIN) \
		$(SHELF_TLS_ARGV_PAYLOAD) $(SHELF_TLS_ARGV_META) $(SHELF_TLS_ARGV_META_BIN) \
		/tmp/strip_headers
	rm -f /tmp/halfshelf_bad_truncated /tmp/halfshelf_bad_magic \
		/tmp/halfshelf_bad_trailing /tmp/halfshelf_bad_memsz \
		/tmp/halfshelf_too_large /tmp/halfshelf.corrupt.out /tmp/halfshelf.corrupt.err
