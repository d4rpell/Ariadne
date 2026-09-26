package normalize

import (
	"strings"
	"testing"
)

func TestRequestedImageComposesDeclaredReference(t *testing.T) {
	valid := []struct {
		name     string
		declared DeclaredImage
		want     string
	}{
		{
			name:     "registry, repository and tag",
			declared: DeclaredImage{Registry: "registry.example", Repository: "app", Tag: "release"},
			want:     "registry.example/app:release",
		},
		{
			name:     "absent tag adds no suffix",
			declared: DeclaredImage{Registry: "registry.example", Repository: "app"},
			want:     "registry.example/app",
		},
		{
			name:     "registry with port",
			declared: DeclaredImage{Registry: "registry.example:5000", Repository: "app", Tag: "release"},
			want:     "registry.example:5000/app:release",
		},
		{
			name:     "bracketed ipv6 host",
			declared: DeclaredImage{Registry: "[2001:db8::1]", Repository: "app"},
			want:     "[2001:db8::1]/app",
		},
		{
			name:     "bracketed ipv6 host with port",
			declared: DeclaredImage{Registry: "[2001:db8::1]:5000", Repository: "app", Tag: "v1"},
			want:     "[2001:db8::1]:5000/app:v1",
		},
		{
			name:     "bare node name",
			declared: DeclaredImage{Registry: "localhost", Repository: "app"},
			want:     "localhost/app",
		},
		{
			name:     "nested repository and case preserved verbatim",
			declared: DeclaredImage{Registry: "REG.example", Repository: "Team/Sub/App", Tag: "v1.2-3_x"},
			want:     "REG.example/Team/Sub/App:v1.2-3_x",
		},
		{
			name:     "leading underscore tag",
			declared: DeclaredImage{Registry: "registry.example", Repository: "app", Tag: "_internal"},
			want:     "registry.example/app:_internal",
		},
	}
	for _, testCase := range valid {
		composed, err := RequestedImage(testCase.declared)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", testCase.name, err)
			continue
		}
		if string(composed) != testCase.want {
			t.Errorf("%s: composed = %q, want %q", testCase.name, composed, testCase.want)
		}
		if strings.Contains(string(composed), "@") {
			t.Errorf("%s: composed reference carries a digest marker", testCase.name)
		}
		if !strings.HasPrefix(string(composed), testCase.declared.Registry+"/") {
			t.Errorf("%s: registry not preserved verbatim", testCase.name)
		}
		again, repeatErr := RequestedImage(testCase.declared)
		if repeatErr != nil || again != composed {
			t.Errorf("%s: composition is not deterministic", testCase.name)
		}
		if testCase.declared.Tag == "" && strings.Contains(string(composed), ":") && !strings.Contains(testCase.declared.Registry, ":") {
			t.Errorf("%s: a tag suffix was added to a declaration without tag", testCase.name)
		}
	}
}

func TestRequestedImageRefusesAmbiguousDeclarations(t *testing.T) {
	cases := map[string]struct{ declared DeclaredImage }{
		"empty registry":                {DeclaredImage{Repository: "app"}},
		"registry with space":           {DeclaredImage{Registry: "reg example", Repository: "app"}},
		"registry with slash":           {DeclaredImage{Registry: "reg/istry", Repository: "app"}},
		"registry with digest marker":   {DeclaredImage{Registry: "reg@istry", Repository: "app"}},
		"registry not ascii":            {DeclaredImage{Registry: "registro.éx", Repository: "app"}},
		"registry with control byte":    {DeclaredImage{Registry: "reg\x01istry", Repository: "app"}},
		"registry with query marker":    {DeclaredImage{Registry: "host?x", Repository: "app"}},
		"registry with fragment marker": {DeclaredImage{Registry: "host#x", Repository: "app"}},
		"registry with percent":         {DeclaredImage{Registry: "host%20x", Repository: "app"}},
		"registry with empty label":     {DeclaredImage{Registry: ".example", Repository: "app"}},
		"registry with trailing dot":    {DeclaredImage{Registry: "example.", Repository: "app"}},
		"registry with leading dash":    {DeclaredImage{Registry: "-host", Repository: "app"}},
		"registry with trailing dash":   {DeclaredImage{Registry: "host-", Repository: "app"}},
		"registry only dot":             {DeclaredImage{Registry: ".", Repository: "app"}},
		"registry only underscore":      {DeclaredImage{Registry: "_", Repository: "app"}},
		"empty port":                    {DeclaredImage{Registry: "registry.example:", Repository: "app"}},
		"port zero":                     {DeclaredImage{Registry: "registry.example:0", Repository: "app"}},
		"port not decimal":              {DeclaredImage{Registry: "registry.example:abc", Repository: "app"}},
		"port above range":              {DeclaredImage{Registry: "registry.example:65536", Repository: "app"}},
		"port far above range":          {DeclaredImage{Registry: "registry.example:99999", Repository: "app"}},
		"two ports":                     {DeclaredImage{Registry: "registry.example:80:90", Repository: "app"}},
		"unbracketed ipv6":              {DeclaredImage{Registry: "2001:db8::1", Repository: "app"}},
		"empty ipv6 host":               {DeclaredImage{Registry: "[]:5000", Repository: "app"}},
		"unterminated ipv6 host":        {DeclaredImage{Registry: "[2001:db8::1", Repository: "app"}},
		"bracketed non ipv6 host":       {DeclaredImage{Registry: "[registry.example]", Repository: "app"}},
		"bracketed ipv4 host":           {DeclaredImage{Registry: "[1.2.3.4]", Repository: "app"}},
		"ipv6 with empty groups":        {DeclaredImage{Registry: "[::::]", Repository: "app"}},
		"ipv6 with two compressions":    {DeclaredImage{Registry: "[1::2::3]", Repository: "app"}},
		"ipv6 with too many groups":     {DeclaredImage{Registry: "[1:2:3:4:5:6:7:8:9]", Repository: "app"}},
		"ipv6 with invalid ipv4 tail":   {DeclaredImage{Registry: "[::ffff:999.999.999.999]", Repository: "app"}},
		"ipv6 with zone identifier":     {DeclaredImage{Registry: "[fe80::1%eth0]", Repository: "app"}},
		"trailing text after ipv6 host": {DeclaredImage{Registry: "[2001:db8::1]x", Repository: "app"}},
		"empty repository":              {DeclaredImage{Registry: "registry.example"}},
		"repository with empty segment": {DeclaredImage{Registry: "registry.example", Repository: "team//app"}},
		"repository leading slash":      {DeclaredImage{Registry: "registry.example", Repository: "/app"}},
		"repository trailing slash":     {DeclaredImage{Registry: "registry.example", Repository: "app/"}},
		"repository current segment":    {DeclaredImage{Registry: "registry.example", Repository: "team/./app"}},
		"repository parent segment":     {DeclaredImage{Registry: "registry.example", Repository: "team/../app"}},
		"repository carrying a tag":     {DeclaredImage{Registry: "registry.example", Repository: "app:release"}},
		"repository carrying a digest":  {DeclaredImage{Registry: "registry.example", Repository: "app@sha256:" + strings.Repeat("ab", 32)}},
		"repository with space":         {DeclaredImage{Registry: "registry.example", Repository: "my app"}},
		"repository with control byte":  {DeclaredImage{Registry: "registry.example", Repository: "app\x7f"}},
		"repository segment not ascii":  {DeclaredImage{Registry: "registry.example", Repository: "ápp"}},
		"repository with query marker":  {DeclaredImage{Registry: "registry.example", Repository: "app?x"}},
		"repository with percent":       {DeclaredImage{Registry: "registry.example", Repository: "app%20x"}},
		"repository with backslash":     {DeclaredImage{Registry: "registry.example", Repository: "team\\app"}},
		"repository with quote":         {DeclaredImage{Registry: "registry.example", Repository: "app\"x"}},
		"repository with semicolon":     {DeclaredImage{Registry: "registry.example", Repository: "app;x"}},
		"repository with bracket":       {DeclaredImage{Registry: "registry.example", Repository: "app[x]"}},
		"tag with slash":                {DeclaredImage{Registry: "registry.example", Repository: "app", Tag: "tag/branch"}},
		"tag with colon":                {DeclaredImage{Registry: "registry.example", Repository: "app", Tag: "tag:branch"}},
		"tag with digest marker":        {DeclaredImage{Registry: "registry.example", Repository: "app", Tag: "tag@sha256"}},
		"tag starting with dot":         {DeclaredImage{Registry: "registry.example", Repository: "app", Tag: ".tag"}},
		"tag starting with dash":        {DeclaredImage{Registry: "registry.example", Repository: "app", Tag: "-tag"}},
		"tag not ascii":                 {DeclaredImage{Registry: "registry.example", Repository: "app", Tag: "tagé"}},
		"tag with control byte":         {DeclaredImage{Registry: "registry.example", Repository: "app", Tag: "tag\x01"}},
		"tag with space":                {DeclaredImage{Registry: "registry.example", Repository: "app", Tag: "tag branch"}},
		"tag too long":                  {DeclaredImage{Registry: "registry.example", Repository: "app", Tag: strings.Repeat("a", maxTagBytes+1)}},
	}
	for name, testCase := range cases {
		composed, err := RequestedImage(testCase.declared)
		if err == nil {
			t.Errorf("%s: accepted, produced %q", name, composed)
			continue
		}
		if composed != "" {
			t.Errorf("%s: refused declaration still produced %q", name, composed)
		}
	}
}

func TestRequestedImageKeepsPortBoundariesVerbatim(t *testing.T) {
	cases := []struct {
		registry string
		want     string
	}{
		{registry: "registry.example:1", want: "registry.example:1/app"},
		{registry: "registry.example:65535", want: "registry.example:65535/app"},
		{registry: "registry.example:0080", want: "registry.example:0080/app"},
		{registry: "[::1]", want: "[::1]/app"},
		{registry: "[::ffff:1.2.3.4]:5000", want: "[::ffff:1.2.3.4]:5000/app"},
	}
	for _, testCase := range cases {
		composed, err := RequestedImage(DeclaredImage{Registry: testCase.registry, Repository: "app"})
		if err != nil {
			t.Errorf("%s: unexpected error: %v", testCase.registry, err)
			continue
		}
		if string(composed) != testCase.want {
			t.Errorf("%s: composed = %q, want %q", testCase.registry, composed, testCase.want)
		}
	}
}

// TestRequestedImageImposesNoLengthLimits pins the ratified scope: the grammar
// bounds shape, not size. Resource bounding comes from the per-field limit of the
// input format (ADR-0007 §4), not from this composer.
func TestRequestedImageImposesNoLengthLimits(t *testing.T) {
	declared := DeclaredImage{
		Registry:   strings.Repeat("registry.example.", 20) + "example",
		Repository: strings.Repeat("segment/", 100) + "app",
	}
	composed, err := RequestedImage(declared)
	if err != nil {
		t.Fatalf("long but well-formed declaration rejected: %v", err)
	}
	if !strings.HasPrefix(string(composed), declared.Registry+"/") {
		t.Fatal("long declaration was rewritten")
	}
}

func TestRequestedImageAcceptsTagAtLengthBoundary(t *testing.T) {
	declared := DeclaredImage{Registry: "registry.example", Repository: "app", Tag: strings.Repeat("a", maxTagBytes)}
	composed, err := RequestedImage(declared)
	if err != nil {
		t.Fatalf("tag at the exact boundary rejected: %v", err)
	}
	if string(composed) != "registry.example/app:"+declared.Tag {
		t.Fatalf("composed = %q", composed)
	}
}
