package gapstone

import "testing"
import "bytes"
import "fmt"
import "io/ioutil"

func TestArm64(t *testing.T) {

	final := new(bytes.Buffer)
	spec_file := "arm64.SPEC"

	for i, platform := range arm64_tests {

		engine, err := New(platform.arch, platform.mode)
		if err != nil {
			fmt.Println(err)
			return
		}
		if i == 0 {
			maj, min := engine.Version()
			fmt.Printf("Testing Capstone Arm64. Version %v.%v\n", maj, min)
		}
		defer engine.Close()
		insns, err := engine.Disasm([]byte(platform.code), 0x2c, 0)
		if err == nil {
			fmt.Fprintf(final, "****************\n")
			fmt.Fprintf(final, "Platform: %s\n", platform.comment)
			dumpCode(platform.code, final)
			fmt.Fprintf(final, "Disasm:\n")
			for _, insn := range insns {
				fmt.Fprintf(final, "0x%x:\t%s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
				insnDetail(insn, &engine, final)
			}
			fmt.Fprintf(final, "0x%x:\n", insns[len(insns)-1].Address+insns[len(insns)-1].Size)
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
	}

}
