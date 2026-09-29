package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/evaluator"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestA108TransportLimits covers C05: every transport role is connected to its
// real constant through execute, with the literal ratified values and the
// N-1/N/N+1 boundaries. The large cases are generated during the test and never
// versioned.
func TestA108TransportLimits(t *testing.T) {
	t.Run("ratified transport constants keep their literal values", func(t *testing.T) {
		checks := []struct {
			name string
			got  int
			want int
		}{
			{"maxBundleInputBytes", maxBundleInputBytes, 134_217_728},
			{"maxContextInputBytes", maxContextInputBytes, 262_144},
			{"rulepack.MaxPackBytes", rulepack.MaxPackBytes, 1_048_576},
			{"maxInputDepth", maxInputDepth, 32},

			{"evaluator.MaxContextTotalBytes", evaluator.MaxContextTotalBytes, 4_096},
			{"evaluator.MaxSourcePins", evaluator.MaxSourcePins, 128},
		}
		for _, check := range checks {
			if check.got != check.want {
				t.Fatalf("%s = %d, want the ratified literal %d", check.name, check.got, check.want)
			}
		}
	})

	t.Run("bundle role rejects N+1 as bundle_read input_limit", func(t *testing.T) {
		figures := composeFixture(t, "F09-unmapped-redhat-package")
		// A file of exactly N bytes is transport-admissible; it may fail later at
		// decode, which is why the assertion below is about the read stage.
		atLimit := writeExactFile(t, "bundle.json", maxBundleInputBytes)
		call, parseFailure := parseArguments([]string{"evaluate",
			"--bundle", atLimit, "--bundle-hash", figures.bundleHash,
			"--pack", figures.pack, "--context", figures.context})
		if parseFailure != nil {
			t.Fatalf("arguments: %v", parseFailure)
		}
		_, failure := readInput(call.value("bundle"), stageBundleRead, maxBundleInputBytes, true, "")
		if failure != nil {
			t.Fatalf("exactly N bundle bytes must pass the read stage: %+v", failure)
		}

		overLimit := writeExactFile(t, "bundle.json", maxBundleInputBytes+1)
		_, failure = readInput(overLimit, stageBundleRead, maxBundleInputBytes, true, "")
		if failure == nil || failure.stage != stageBundleRead || failure.code != codeInputLimit || failure.exit != 3 {
			t.Fatalf("N+1 bundle bytes = %+v, want bundle_read/input_limit/3", failure)
		}
	})

	t.Run("context role rejects N+1 as context_read input_limit", func(t *testing.T) {
		atLimit := writeExactFile(t, "context.json", maxContextInputBytes)
		if _, failure := readInput(atLimit, stageContextRead, maxContextInputBytes, true, ""); failure != nil {
			t.Fatalf("exactly N context bytes must pass the read stage: %+v", failure)
		}
		overLimit := writeExactFile(t, "context.json", maxContextInputBytes+1)
		_, failure := readInput(overLimit, stageContextRead, maxContextInputBytes, true, "")
		if failure == nil || failure.stage != stageContextRead || failure.code != codeInputLimit || failure.exit != 3 {
			t.Fatalf("N+1 context bytes = %+v, want context_read/input_limit/3", failure)
		}
	})

	t.Run("pack role rejects N+1 as pack_read input_limit", func(t *testing.T) {
		atLimit := writeExactFile(t, "pack.json", rulepack.MaxPackBytes)
		if _, failure := readInput(atLimit, stagePackRead, rulepack.MaxPackBytes, false, ""); failure != nil {
			t.Fatalf("exactly N pack bytes must pass the read stage: %+v", failure)
		}
		overLimit := writeExactFile(t, "pack.json", rulepack.MaxPackBytes+1)
		_, failure := readInput(overLimit, stagePackRead, rulepack.MaxPackBytes, false, "")
		if failure == nil || failure.stage != stagePackRead || failure.code != codeInputLimit || failure.exit != 3 {
			t.Fatalf("N+1 pack bytes = %+v, want pack_read/input_limit/3", failure)
		}
	})

	t.Run("the three roles are connected to the command", func(t *testing.T) {
		// Every role — bundle, context and pack — must reach its real constant
		// through the command, not only through readInput: the limit is observed
		// as the role's input_limit of the whole run, with the other roles valid.
		figures := composeFixture(t, "F09-unmapped-redhat-package")
		cases := []struct {
			name  string
			stage string
			argv  []string
			// laterStage/laterCode are the exact failure the zero-filled document
			// must produce after the read stage admits it: a different early
			// failure would prove the read limit fired below N+1.
			laterStage string
			laterCode  string
		}{
			{"bundle", stageBundleRead, []string{"evaluate", "--bundle-hash", figures.bundleHash,
				"--pack", figures.pack, "--context", figures.context}, stageBundleDecode, codeInvalidBundle},
			{"context", stageContextRead, []string{"evaluate", "--bundle", figures.bundle,
				"--bundle-hash", figures.bundleHash, "--pack", figures.pack}, stageContextDecode, codeInvalidContext},
			{"pack", stagePackRead, []string{"evaluate", "--bundle", figures.bundle,
				"--bundle-hash", figures.bundleHash, "--context", figures.context}, stageEvaluate, "pack_hash_mismatch"},
		}
		flagOf := map[string]string{"bundle": "--bundle", "context": "--context", "pack": "--pack"}
		sizeOf := map[string]int64{"bundle": maxBundleInputBytes, "context": maxContextInputBytes, "pack": rulepack.MaxPackBytes}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				refusedAtRead := `"stage":"` + tc.stage + `","code":"input_limit"`
				// N-1 and N through the command: the read stage admits the bytes and
				// the observable failure is the later stage of the zero-filled
				// document. Excluding only the read diagnostic would let any other
				// early failure pass, so the later failure is named exactly.
				for _, size := range []int{int(sizeOf[tc.name]) - 1, int(sizeOf[tc.name])} {
					label := "N-1"
					if size == int(sizeOf[tc.name]) {
						label = "N"
					}
					path := writeExactFile(t, tc.name+"-at.json", size)
					argv := append(append([]string{}, tc.argv...), flagOf[tc.name], path)
					exit, stdout, stderr := runCLI(t, argv)
					if strings.Contains(stderr, refusedAtRead) {
						t.Fatalf("%s at %s was refused by the read limit: %s", tc.name, label, stderr)
					}
					if exit == 0 || stdout != "" {
						t.Fatalf("%s at %s: exit = %d, stdout = %q; the zero-filled document must fail later", tc.name, label, exit, stdout)
					}
					if !strings.Contains(stderr, `"stage":"`+tc.laterStage+`"`) || !strings.Contains(stderr, `"code":"`+tc.laterCode+`"`) {
						t.Fatalf("%s at %s: stderr = %q, want the later %s/%s failure", tc.name, label, stderr, tc.laterStage, tc.laterCode)
					}
				}
				over := writeExactFile(t, tc.name+"-over.json", int(sizeOf[tc.name])+1)
				argvOver := append(append([]string{}, tc.argv...), flagOf[tc.name], over)
				exit, stdout, stderr := runCLI(t, argvOver)
				if exit != 3 || stdout != "" {
					t.Fatalf("exit = %d, stdout = %q; want the transport rejection", exit, stdout)
				}
				want := `{"error":{"stage":"` + tc.stage + `","code":"input_limit","message":"ariadne: input_limit"}}` + "\n"
				if stderr != want {
					t.Fatalf("stderr = %q, want %q", stderr, want)
				}
			})
		}
	})

	t.Run("context depth is enforced through the command", func(t *testing.T) {
		figures := composeFixture(t, "F09-unmapped-redhat-package")
		overDepth := strings.Repeat("[", maxInputDepth+1) + strings.Repeat("]", maxInputDepth+1)
		overPath := writeTemp(t, "context-over.json", []byte(overDepth))
		exit, stdout, stderr := runCLI(t, []string{"evaluate",
			"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
			"--pack", figures.pack, "--context", overPath})
		if exit != 3 || stdout != "" {
			t.Fatalf("context over N levels: exit = %d, stdout = %q", exit, stdout)
		}
		want := `{"error":{"stage":"context_read","code":"input_limit","message":"ariadne: input_limit"}}` + "\n"
		if stderr != want {
			t.Fatalf("stderr = %q, want %q", stderr, want)
		}
	})

	t.Run("envelope depth rejects at N+1", func(t *testing.T) {
		// Depth is counted on the decoded document: an object at the root is
		// depth 1. A document one level past the limit is refused as input_limit
		// of the decode stage.
		// The depth of the envelope is enforced at the read role: documents of N
		// and N-1 levels are admitted by the depth rule, N+1 is refused as the
		// transport limit of that role.
		atDepth := strings.Repeat("[", maxInputDepth) + strings.Repeat("]", maxInputDepth)
		path := writeTemp(t, "deep.json", []byte(atDepth))
		if _, failure := readInput(path, stageBundleRead, maxBundleInputBytes, true, ""); failure != nil {
			t.Fatalf("a document of exactly N levels must pass the depth rule: %+v", failure)
		}
		overDepth := strings.Repeat("[", maxInputDepth+1) + strings.Repeat("]", maxInputDepth+1)
		overPath := writeTemp(t, "deep.json", []byte(overDepth))
		_, failure := readInput(overPath, stageBundleRead, maxBundleInputBytes, true, "")
		if failure == nil || failure.code != codeInputLimit || failure.stage != stageBundleRead || failure.exit != 3 {
			t.Fatalf("N+1 levels = %+v, want bundle_read/input_limit/3", failure)
		}
	})

	t.Run("model preflight rejects before the encoder", func(t *testing.T) {
		figures := composeFixture(t, "F09-unmapped-redhat-package")
		canonical := readTemp(t, figures.bundle)
		var decoded contract.Bundle
		if err := json.Unmarshal(canonical, &decoded); err != nil {
			t.Fatalf("decode fixture: %v", err)
		}
		decoded.Evidence = make([]contract.EvidenceItem, evaluator.MaxEvidenceItems+1)
		over := marshalForTest(t, decoded)

		original := canonicalEncode
		defer func() { canonicalEncode = original }()
		encoded := false
		canonicalEncode = func(input contract.Bundle) (bundleArtifacts, error) {
			encoded = true
			return original(input)
		}
		_, failure := decodeBundle(over)
		if failure == nil || failure.code != codeInputLimit {
			t.Fatalf("oversized model = %+v, want input_limit", failure)
		}
		if encoded {
			t.Fatal("the encoder ran for a model that exceeds a budget")
		}
	})

	t.Run("a model budget rejection reads as the decode stage", func(t *testing.T) {
		figures := composeFixture(t, "F09-unmapped-redhat-package")
		canonical := readTemp(t, figures.bundle)
		var decoded contract.Bundle
		if err := json.Unmarshal(canonical, &decoded); err != nil {
			t.Fatalf("decode fixture: %v", err)
		}
		decoded.Images = make([]contract.ImageIdentity, evaluator.MaxImages+1)
		over := marshalForTest(t, decoded)
		path := writeTemp(t, "bundle.json", over)
		contextPath := writeTemp(t, "context.json", []byte(`{}`))
		exit, stdout, stderr := runCLI(t, []string{"evaluate",
			"--bundle", path, "--bundle-hash", figures.bundleHash,
			"--pack", figures.pack, "--context", contextPath})
		if exit != 3 || stdout != "" {
			t.Fatalf("exit = %d, stdout = %q", exit, stdout)
		}
		if !strings.Contains(stderr, `"stage":"bundle_decode"`) || !strings.Contains(stderr, `"code":"input_limit"`) {
			t.Fatalf("stderr = %q, want bundle_decode/input_limit", stderr)
		}
	})
}

// bundleArtifacts is the artifact shape the encoder seam returns.
type bundleArtifacts = bundle.Artifacts

// writeExactFile writes a file of an exact size in a private directory. It exists
// so the transport boundaries are generated during the test and never versioned.
func writeExactFile(t *testing.T, name string, size int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}
