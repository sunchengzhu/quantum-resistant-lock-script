cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/..

CLANG := $(shell $(cur_dir)/scripts/find_clang)
CLANGXX := $(subst clang,clang++,$(CLANG))
LD := $(subst clang,ld.lld,$(CLANG))
OBJCOPY := $(subst clang,llvm-objcopy,$(CLANG))
AR := $(subst clang,llvm-ar,$(CLANG))
RANLIB := $(subst clang,llvm-ranlib,$(CLANG))

PARAMS := sphincs-sha2-256f
THASH := simple
RUST_PARAM_FEATURES := sha2,hash_256,hash_options_f,thashes_simple

CORPUS := $(cur_dir)/corpus
TOOLKIT := $(cur_dir)/ckb-script-fuzzing-toolkit

TRACER := ckb-vm-syscall-tracer

DOCKER := docker
DOCKER_IMAGE := docker.io/xxuejie/ckb-script-fuzzing-toolkit:20250625
DOCKER_RUN_ARGS :=

.PHONY: repl
repl:
	$(DOCKER) run --rm -it $(DOCKER_RUN_ARGS) -v $(TOP):/code $(DOCKER_IMAGE) || true
	$(DOCKER) run --rm -it $(DOCKER_RUN_ARGS) -e UID=`id -u` -e GID=`id -g` -v $(TOP):/code $(DOCKER_IMAGE) bash -c 'chown -R -f $$UID:$$GID .'

.PHONY: clean
clean:
	rm -rf $(CORPUS) objs libfuzzer-protobuf hfuzz-protobuf
	make -C $(TOP) -f Makefile.clang clean
	cd $(TOP)/tests/sphincsplus_rust; cargo clean

.PHONY: generate-corpus
generate-corpus:
	make -C $(TOP) -f Makefile.clang \
		CC=$(CLANG) LD=$(LD) OBJCOPY=$(OBJCOPY) AR=$(AR) RANLIB=$(RANLIB) \
		PARAMS=$(PARAMS)
	rm -rf $(CORPUS)
	cd $(TOP)/tests/sphincsplus_rust; \
		DUMP_TXS_PATH=$(CORPUS)/txs cargo test \
		--no-default-features --features $(RUST_PARAM_FEATURES)
	for f in `find $(CORPUS)/txs -type f`; do \
		$(TRACER) -t $$f -o $(CORPUS)/_data --cell-index 0; \
		mv $(CORPUS)/_data/vm_0_0.traces $(CORPUS)/$$(basename $$f).data; \
	done
	rm -rf $(CORPUS)/txs $(CORPUS)/_data

# Copied over from $(TOP)/Makefile to setup sources to build
SPHINCS_PLUS_DIR = deps/sphincsplus/ref/

SOURCES = \
	$(SPHINCS_PLUS_DIR)address.c \
	$(SPHINCS_PLUS_DIR)merkle.c \
	$(SPHINCS_PLUS_DIR)wots.c \
	$(SPHINCS_PLUS_DIR)wotsx1.c \
	$(SPHINCS_PLUS_DIR)utils.c \
	$(SPHINCS_PLUS_DIR)utilsx1.c \
	$(SPHINCS_PLUS_DIR)fors.c \
	$(SPHINCS_PLUS_DIR)sign.c \
	c/ckb-sphincsplus.c

HEADERS = \
	$(SPHINCS_PLUS_DIR)params.h \
	$(SPHINCS_PLUS_DIR)address.h \
	$(SPHINCS_PLUS_DIR)merkle.h \
	$(SPHINCS_PLUS_DIR)wots.h \
	$(SPHINCS_PLUS_DIR)wotsx1.h \
	$(SPHINCS_PLUS_DIR)utils.h \
	$(SPHINCS_PLUS_DIR)utilsx1.h \
	$(SPHINCS_PLUS_DIR)fors.h \
	$(SPHINCS_PLUS_DIR)api.h \
	$(SPHINCS_PLUS_DIR)hash.h \
	$(SPHINCS_PLUS_DIR)thash.h \
	$(SPHINCS_PLUS_DIR)randombytes.h \
	c/ckb-sphincsplus.h

ifneq (,$(findstring shake,$(PARAMS)))
	SOURCES += \
		$(SPHINCS_PLUS_DIR)fips202.c \
		$(SPHINCS_PLUS_DIR)hash_shake.c \
		$(SPHINCS_PLUS_DIR)thash_shake_$(THASH).c
	HEADERS += $(SPHINCS_PLUS_DIR)fips202.h
endif
ifneq (,$(findstring haraka,$(PARAMS)))
	SOURCES += \
		$(SPHINCS_PLUS_DIR)haraka.c \
		$(SPHINCS_PLUS_DIR)hash_haraka.c \
		$(SPHINCS_PLUS_DIR)thash_haraka_$(THASH).c
	HEADERS += $(SPHINCS_PLUS_DIR)haraka.h
endif
ifneq (,$(findstring sha2,$(PARAMS)))
	SOURCES += \
		$(SPHINCS_PLUS_DIR)sha2.c \
		$(SPHINCS_PLUS_DIR)hash_sha2.c \
		$(SPHINCS_PLUS_DIR)thash_sha2_$(THASH).c
	HEADERS += $(SPHINCS_PLUS_DIR)sha2.h
endif

SOURCES += c/ckb-sphincsplus-lock.c
# End of sphincsplus source setup

OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

CFLAGS := -g -Wall -O3 -include "stdbool.h" \
	-I $(TOOLKIT)/include \
	-I $(TOP)/deps/ckb-c-stdlib -I $(TOP)/deps/ckb-c-stdlib/molecule \
	-I $(TOP)/$(SPHINCS_PLUS_DIR) -DPARAMS=$(PARAMS) \
	-DFUZZING -DCKB_VM

PKGCONFIG := pkg-config
HFUZZ_CLANG := hfuzz-clang
HFUZZ_CLANGXX := hfuzz-clang++

libfuzzer-protobuf: $(foreach obj,$(OBJECTS),objs/libfuzzer/$(obj)) $(TOOLKIT)/obj/libckb-fuzzing-libfuzzer-protobuf.a
	$(CLANGXX) -o $@ $^ \
		-fsanitize=fuzzer,address,undefined -fno-sanitize=alignment \
		$(shell $(PKGCONFIG) --libs libprotobuf-mutator) \
		$(shell $(PKGCONFIG) --libs protobuf)

hfuzz-protobuf: $(foreach obj,$(OBJECTS),objs/hfuzz/$(obj)) $(TOOLKIT)/obj/libckb-fuzzing-hfuzz-protobuf.a
	$(HFUZZ_CLANGXX) -o $@ $^ \
		-fsanitize=address,undefined -fno-sanitize=alignment \
		$(shell $(PKGCONFIG) --libs libprotobuf-mutator) \
		$(shell $(PKGCONFIG) --libs protobuf)

$(TOOLKIT)/obj/libckb-fuzzing-libfuzzer-protobuf.a:
	make -C $(TOOLKIT) libfuzzer

$(TOOLKIT)/obj/libckb-fuzzing-hfuzz-protobuf.a:
	make -C $(TOOLKIT) hfuzz

objs/libfuzzer/%.o: $(TOP)/%.c
	mkdir -p $(dir $@)
	$(CLANG) -c -o $@ $< $(CFLAGS) -fsanitize=fuzzer,address,undefined -fno-sanitize=alignment

objs/hfuzz/%.o: $(TOP)/%.c
	mkdir -p $(dir $@)
	$(HFUZZ_CLANG) -c -o $@ $< $(CFLAGS) -fsanitize=address,undefined -fno-sanitize=alignment

.PHONY: fuzz
fuzz: $(TOOLKIT)/obj/libckb-fuzzing-hfuzz-protobuf.a
	@echo $(OBJECTS)
