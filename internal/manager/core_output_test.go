package manager

import (
	"strings"
	"testing"
)

func TestCoreStartupOutputRecognizesOnlyCompleteKnownLines(t *testing.T) {
	for _, failure := range coreStartupFailures {
		t.Run(failure.code+"/"+failure.line, func(t *testing.T) {
			output := newCoreStartupOutput()
			// exec's pipe writes can split a message at any byte.
			for _, b := range []byte(failure.line + "\n") {
				if n, err := output.Write([]byte{b}); err != nil || n != 1 {
					t.Fatal("startup output writer failed to drain")
				}
			}
			if output.errorCode() != failure.code {
				t.Fatal("known startup message did not become its public enum")
			}
		})
	}
}

func TestCoreStartupOutputDiscardsUntrustedText(t *testing.T) {
	known := "[DAEMON] configuration_failed: invalid VK call hash"
	for _, input := range []string{
		"arbitrary-test-secret https://example.invalid/private-call\n",
		"[DAEMON] configuration_failed: unknown private server response\n",
		known,
		known + " private-test-secret\n",
		"prefix " + known + "\n",
		known + "\r\n",
		"[PANIC] Rust client task failed: private-test-secret\n",
	} {
		output := newCoreStartupOutput()
		_, _ = output.Write([]byte(input))
		if output.errorCode() != "" {
			t.Fatal("untrusted or incomplete text became a public error")
		}
	}
	output := newCoreStartupOutput()
	_, _ = output.Write([]byte("unknown private line\n" + known + "\n"))
	if output.errorCode() != "core_config_vk_invalid" {
		t.Fatal("discarded text prevented recognizing a later complete line")
	}
}

func TestCoreStartupOutputBoundsInspectionAndContinuesDraining(t *testing.T) {
	known := "[PANIC] Rust client task failed\n"
	// A message ending exactly at the inspection limit is still complete.
	output := newCoreStartupOutput()
	boundary := strings.Repeat("\n", maxStartupOutput-len(known)) + known
	if n, err := output.Write([]byte(boundary)); err != nil || n != len(boundary) || output.errorCode() != "core_runtime_panic" {
		t.Fatal("complete message at inspection boundary was lost")
	}
	output = newCoreStartupOutput()
	input := strings.Repeat("\n", maxStartupOutput-len(known)+1) + known
	_, _ = output.Write([]byte(input))
	if output.errorCode() != "" || output.inspected != maxStartupOutput {
		t.Fatal("output beyond the inspection limit was recognized")
	}
	flood := []byte(strings.Repeat("ignored private test text\n", maxStartupOutput))
	if n, err := output.Write(flood); err != nil || n != len(flood) || output.inspected != maxStartupOutput || output.errorCode() != "" {
		t.Fatal("discarded output was not fully drained within the fixed inspection budget")
	}
}
