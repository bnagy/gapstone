package gapstone

import "testing"
import "bytes"
import "fmt"
import "io/ioutil"

func TestTest(t *testing.T) {

	final := new(bytes.Buffer)
	spec_file := "test.SPEC"
	var maj, min int
	if ver, err := New(0, 0); err == nil {
		maj, min = ver.Version()
		ver.Close()
	}
	t.Logf("Basic Test. Capstone Version: %v.%v", maj, min)
	for i, platform := range basic_tests {
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
				fmt.Fprintf(final, "0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
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
		fmt.Println(fs)
		t.Errorf("Output failed to match spec!")
	} else {
		t.Logf("Clean diff with %v.\n", spec_file)
	}

}
