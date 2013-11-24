package gapstone

import "testing"
import "bytes"
import "fmt"
import "io/ioutil"

func TestDetailTest(t *testing.T) {

	final := new(bytes.Buffer)

	spec_file := "test_detail.SPEC"
	ver, err := New(0, 0)
	maj, min := ver.Version()
	ver.Close()

	// All the tests are the same except ARM64 :<
	t.Logf("Detailed Test. Capstone Version: %v.%v", maj, min)
	detail_tests := append([]platform{}, basic_tests...)
	detail_tests[len(detail_tests)-1] = platform{
		CS_ARCH_ARM64,
		CS_MODE_ARM,
		"\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x10\x20\x21\x1e",
		"ARM-64",
	}

	for i, platform := range detail_tests {

		t.Logf("%2d> %s", i, platform.comment)
		engine, err := New(platform.arch, platform.mode)
		if err != nil {
			t.Errorf("Failed to initialize engine %v", err)
			return
		}
		defer engine.Close()

		insns, err := engine.Disasm([]byte(platform.code), OFFSET, 0)
		if err == nil {
			fmt.Fprintf(final, "****************\n")
			fmt.Fprintf(final, "Platform: %s\n", platform.comment)
			fmt.Fprintf(final, "Code: ")
			dumpHex([]byte(platform.code), final)
			fmt.Fprintf(final, "Disasm:\n")
			for _, insn := range insns {
				fmt.Fprintf(
					final,
					"0x%x:\t%s\t\t%s // insn-ID: %v, insn-mnem: %s\n",
					insn.Address,
					insn.Mnemonic,
					insn.OpStr,
					insn.Id,
					engine.InsnName(insn.Id),
				)
				if len(insn.RegistersRead) > 0 {
					fmt.Fprint(final, "\tImplicit registers read: ")
					for _, reg := range insn.RegistersRead {
						fmt.Fprintf(final, "%s ", engine.RegName(reg))
					}
					fmt.Fprintf(final, "\n")
				}
				if len(insn.RegistersWritten) > 0 {
					fmt.Fprint(final, "\tImplicit registers modified: ")
					for _, reg := range insn.RegistersWritten {
						fmt.Fprintf(final, "%s ", engine.RegName(reg))
					}
					fmt.Fprintf(final, "\n")
				}
				if len(insn.Groups) > 0 {
					fmt.Fprintf(final, "\tThis instruction belongs to groups: ")
					for _, grp := range insn.Groups {
						fmt.Fprintf(final, "%v ", grp)
					}
					fmt.Fprintf(final, "\n")
				}
			}
			fmt.Fprintf(final, "0x%x:\n", insns[len(insns)-1].Address+insns[len(insns)-1].Size)
			fmt.Fprintf(final, "\n")
		} else {
			t.Errorf("Disassembly error: %v\n", err)
		}

	}

	spec, err := ioutil.ReadFile(spec_file)
	if err != nil {
		t.Errorf("Cannot read spec file %v: %v", spec_file, err)
	}
	if fs := final.String(); string(spec) != fs {
		//fmt.Println(fs)
		t.Errorf("Output failed to match spec!")
	} else {
		t.Logf("Clean diff with %v.\n", spec_file)
	}

}
