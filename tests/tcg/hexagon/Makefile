-include ../../../config-host.mak

SIM = qemu-hexagon
REF = hexagon-sim

CC := hexagon-clang
C_CFLAGS := -O1
ASM_CFLAGS := -O0
LDFLAGS := -static -nostdlib
REFFLAGS := -t trace.log

TSRC_PATH = $(SRC_PATH)/tests/tcg/hexagon

CRT        = crt.o
#TESTCASES += test_vcmp.tst
TESTCASES += test_abs.tst
TESTCASES += test_add.tst
TESTCASES += test_andp.tst
TESTCASES += test_bitcnt.tst
TESTCASES += test_bitsplit.tst
TESTCASES += test_call.tst
TESTCASES += test_clobber.tst
TESTCASES += test_cmp.tst
TESTCASES += test_cmpy.tst
TESTCASES += test_djump.tst
TESTCASES += test_dotnew.tst
TESTCASES += test_dstore.tst
TESTCASES += test_ext.tst
TESTCASES += test_fibonacci.tst
TESTCASES += test_hello.tst
TESTCASES += test_hl.tst
TESTCASES += test_hwloops.tst
TESTCASES += test_jmp.tst
TESTCASES += test_lsr.tst
TESTCASES += test_mem.tst
TESTCASES += test_mpyi.tst
TESTCASES += test_packet.tst
TESTCASES += test_reorder.tst
TESTCASES += test_round.tst
TESTCASES += test_sys_access.tst
TESTCASES += test_sys_clock.tst
TESTCASES += test_sys_close.tst
TESTCASES += test_sys_cmdline.tst
TESTCASES += test_sys_flen.tst
TESTCASES += test_sys_ftell.tst
TESTCASES += test_sys_ftrunc.tst
TESTCASES += test_sys_getcwd.tst
TESTCASES += test_sys_gettimeofday.tst
TESTCASES += test_sys_heapinfo.tst
TESTCASES += test_sys_istty.tst
TESTCASES += test_sys_mkdir.tst
TESTCASES += test_sys_open.tst
TESTCASES += test_sys_opendir.tst
TESTCASES += test_sys_read.tst
TESTCASES += test_sys_readc.tst
TESTCASES += test_sys_rmdir.tst
TESTCASES += test_sys_seek.tst
TESTCASES += test_vavgw.tst
TESTCASES += test_vcmpb.tst
TESTCASES += test_vcmpw.tst
TESTCASES += test_vcmpy.tst
TESTCASES += test_vlsrw.tst
TESTCASES += test_vmaxh.tst
TESTCASES += test_vminh.tst
TESTCASES += test_vpmpyh.tst
TESTCASES += test_vspliceb.tst

all: build

%.o: $(TSRC_PATH)/%.c
	$(CC) $(C_CFLAGS) -c $< -o $@

%.o: $(TSRC_PATH)/%.s
	$(CC) $(ASM_CFLAGS) -c $< -o $@

%.tst: %.o $(CRT)
	$(CC) $(LDFLAGS) $(NOSTDFLAGS) $(CRT) $(CRT_STANDALONE) $< -o $@

build: $(TESTCASES)

check: $(TESTCASES:test_%.tst=check_%)

check_%: test_%.tst test_file.txt
	@echo "Running test: "$<
	@rm -rf opendir_test_folder mkdir_test_folder rmdir_test_folder
	@if [ "$<" = "test_sys_readc.tst" ]; then\
		echo "#\n" | $(SIM) $(SIMFLAGS) $<; \
	 else \
	 	$(SIM) $(SIMFLAGS) $<; \
	 fi;

reference: $(TESTCASES:test_%.tst=reference_%)

reference_%: test_%.tst test_file.txt
	@echo "Running reference test: "$<
	@rm -rf opendir_test_folder mkdir_test_folder rmdir_test_folder
	@if [ "$<" = "test_sys_readc.tst" ]; then\
		echo "#\n" | $(REF) $(SIMFLAGS) $<; \
	 else \
	 	$(REF) $(REFFLAGS) $<; \
		grep "r01\s*:\s*0x00000000.*r03\s*:\s*0xdeadb00b" trace.log; \
	 fi;

test_file.txt:
	@echo "Creating test files"
	@echo "Thank you Fabrice!" > test_file.txt

clean:
	$(RM) -fr $(TESTCASES) $(CRT) $(HELPER) *.core trunc_test_file.txt \
    trace.log opendir_test_folder mkdir_test_folder rmdir_test_folder \
	pmu_statsfile.txt test_file.txt
