package collector

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// AX-02: the redaction frontier of the live acquisition (T7 of
// ARQUITECTURE.md §8) seen at the published boundary. The projection tests pin the
// sanitized source member by member; this test composes the whole published
// surface of one run — the sanitized capture bytes, the artefacts of every
// built bundle and the whole acquisition record — and demands that no value of
// a discarded API location survive in any of them.
//
// Every canary below is synthetic and distinct, so a failure names the exact
// location that leaked.

const (
	ax02Edit        = "AX02CANARY-edit"
	ax02ListMeta    = "AX02CANARY-listemeta"
	ax02Labels      = "AX02CANARY-labels"
	ax02Annotations = "AX02CANARY-annotations"
	ax02Finalizers  = "AX02CANARY-finalizers"
	ax02Generate    = "AX02CANARY-generatename"
	ax02Managed     = "AX02CANARY-managedfields"
	ax02Created     = "AX02CANARY-created"
	ax02ServiceAcct = "AX02CANARY-serviceaccount"
	ax02NodeName    = "AX02CANARY-nodename"
	ax02Priority    = "AX02CANARY-priority"
	ax02PullSecrets = "AX02CANARY-pullsecrets"
	ax02Volume      = "AX02CANARY-volume"
	ax02ConfigMap   = "AX02CANARY-configmap"
	ax02Toleration  = "AX02CANARY-toleration"
	ax02PodSecurity = "AX02CANARY-podsecuritycontext"
	ax02Env         = "AX02CANARY-env"
	ax02EnvFrom     = "AX02CANARY-envfrom"
	ax02EnvValueFrm = "AX02CANARY-envvaluefrom"
	ax02Args        = "AX02CANARY-args"
	ax02Command     = "AX02CANARY-command"
	ax02Workdir     = "AX02CANARY-workingdir"
	ax02Mount       = "AX02CANARY-volumemount"
	ax02Resources   = "AX02CANARY-resources"
	ax02Probe       = "AX02CANARY-livenessprobe"
	ax02StatusMsg   = "AX02CANARY-statusmessage"
	ax02StatusRsn   = "AX02CANARY-statusreason"
	ax02PodIP       = "AX02CANARY-podip"
	ax02Nominated   = "AX02CANARY-nominatednode"
	ax02QoS         = "AX02CANARY-qosclass"
	ax02Condition   = "AX02CANARY-condition"
	ax02ContainerID = "AX02CANARY-containerid"
	ax02LastState   = "AX02CANARY-laststate"
	ax02Terminated  = "AX02CANARY-terminatedmessage"
)

// ax02Canaries is the closed list this test sweeps for, one canary per
// discarded location: a leak is attributable to a single location, and the
// field walk reports every leaked path in one failure instead of the first.
var ax02Canaries = []string{
	ax02Edit, ax02ListMeta, ax02Labels, ax02Annotations, ax02Finalizers,
	ax02Generate, ax02Managed, ax02Created, ax02ServiceAcct, ax02NodeName,
	ax02Priority, ax02PullSecrets, ax02Volume, ax02ConfigMap, ax02Toleration,
	ax02PodSecurity, ax02Env, ax02EnvFrom, ax02EnvValueFrm, ax02Args,
	ax02Command, ax02Workdir, ax02Mount, ax02Resources, ax02Probe,
	ax02StatusMsg, ax02StatusRsn, ax02PodIP, ax02Nominated, ax02QoS,
	ax02Condition, ax02ContainerID, ax02LastState, ax02Terminated,
}

// ax02Pod is one complete Pod whose every discarded location carries its own
// canary and whose admitted fields carry the identity the run needs.
func ax02Pod() string {
	return `{"apiVersion":"v1","kind":"Pod",` +
		`"metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1","resourceVersion":"9",` +
		`"generateName":"` + ax02Generate + `","creationTimestamp":"` + ax02Created + `",` +
		`"labels":{"leak":"` + ax02Labels + `"},"annotations":{"leak":"` + ax02Annotations + `"},` +
		`"finalizers":["` + ax02Finalizers + `"],"managedFields":[{"manager":"` + ax02Managed + `"}]},` +
		`"spec":{"serviceAccountName":"` + ax02ServiceAcct + `","nodeName":"` + ax02NodeName + `",` +
		`"priorityClassName":"` + ax02Priority + `","dnsPolicy":"ClusterFirst",` +
		`"imagePullSecrets":[{"name":"` + ax02PullSecrets + `"}],` +
		`"volumes":[{"name":"v","secret":{"secretName":"` + ax02Volume + `"}},{"name":"c","configMap":{"name":"` + ax02ConfigMap + `"}}],` +
		`"tolerations":[{"key":"` + ax02Toleration + `"}],` +
		`"securityContext":{"runAsUser":1000,"fsGroup":2000,"supplementalGroups":[3000],"seccompProfile":{"localhostProfile":"` + ax02PodSecurity + `"}},` +
		`"containers":[{"name":"api","image":"` + a202Image + `","imagePullPolicy":"IfNotPresent",` +
		`"command":["/bin/sh","-c","` + ax02Command + `"],"args":["` + ax02Args + `"],` +
		`"workingDir":"` + ax02Workdir + `",` +
		`"env":[{"name":"TOKEN","value":"` + ax02Env + `"},{"name":"KEY","valueFrom":{"secretKeyRef":{"name":"` + ax02EnvValueFrm + `","key":"k"}}}],` +
		`"envFrom":[{"configMapRef":{"name":"` + ax02EnvFrom + `"}}],` +
		`"volumeMounts":[{"name":"v","mountPath":"/` + ax02Mount + `"}],` +
		`"resources":{"limits":{"cpu":"100m","memory":"` + ax02Resources + `"}},` +
		`"livenessProbe":{"httpGet":{"path":"/` + ax02Probe + `","port":8080}},` +
		`"securityContext":{"privileged":true,"runAsUser":0},` +
		`"ports":[{"containerPort":8080}]}],` +
		`"initContainers":[],"ephemeralContainers":[],"restartPolicy":"Always"},` +
		`"status":{"phase":"Running","message":"` + ax02StatusMsg + `","reason":"` + ax02StatusRsn + `",` +
		`"podIP":"` + ax02PodIP + `","hostIP":"10.0.0.1","qosClass":"` + ax02QoS + `",` +
		`"startTime":"2026-10-07T09:00:00Z","nominatedNodeName":"` + ax02Nominated + `",` +
		`"conditions":[{"type":"Ready","status":"True","message":"` + ax02Condition + `"}],` +
		`"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `",` +
		`"ready":true,"restartCount":0,"started":true,"containerID":"containerd://` + ax02ContainerID + `",` +
		`"state":{"running":{"startedAt":"2026-10-07T09:00:01Z"}},` +
		`"lastState":{"terminated":{"exitCode":1,"reason":"` + ax02LastState + `","message":"` + ax02Terminated + `"}},` +
		`"allocatedResources":{"cpu":"100m"}}],` +
		`"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
}

// ax02ListDocument is the pinned list response: the Pod plus canaries in the
// discarded root and list-metadata locations, which are never part of the
// sanitized grammar.
func ax02ListDocument() string {
	return `{"apiVersion":"v1","kind":"PodList",` +
		`"metadata":{"resourceVersion":"100","remainingItemCount":3,"labels":{"leak":"` + ax02ListMeta + `"}},` +
		`"warnings":[{"message":"` + ax02Edit + `"}],"items":[` + ax02Pod() + `]}`
}

// ax02PodDocument is the pinned get response: the same Pod, now as the object
// document the get operation expects.
func ax02PodDocument() string { return ax02Pod() }

// ax02Leaks walks a published value and returns the path of every string or
// byte field that carries one of the canaries. It never marshals: a []byte
// would be base64-encoded by encoding/json and the search would go blind.
func ax02Leaks(root any, canaries []string) []string {
	found := []string{}
	ax02Walk(reflect.ValueOf(root), "root", canaries, &found)
	return found
}

// ax02Walk visits every text and byte field of a published value: strings,
// []byte, byte arrays, struct fields, pointers, interfaces, slice and array
// elements, and the keys and values of every map. It never marshals: a []byte
// would be base64-encoded by encoding/json and the search would go blind. Byte
// arrays are read element by element so a read-only or unexported value never
// panics.
func ax02Walk(value reflect.Value, path string, canaries []string, found *[]string) {
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			return
		}
		ax02Walk(value.Elem(), path, canaries, found)
	case reflect.Struct:
		kind := value.Type()
		for index := 0; index < value.NumField(); index++ {
			ax02Walk(value.Field(index), path+"."+kind.Field(index).Name, canaries, found)
		}
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			data := make([]byte, value.Len())
			for index := 0; index < value.Len(); index++ {
				data[index] = byte(value.Index(index).Uint())
			}
			for _, canary := range canaries {
				if bytes.Contains(data, []byte(canary)) {
					*found = append(*found, path)
				}
			}
			return
		}
		for index := 0; index < value.Len(); index++ {
			ax02Walk(value.Index(index), fmt.Sprintf("%s[%d]", path, index), canaries, found)
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			entry := fmt.Sprintf("%s[%v]", path, iterator.Key())
			ax02Walk(iterator.Key(), entry+".key", canaries, found)
			ax02Walk(iterator.Value(), entry, canaries, found)
		}
	case reflect.String:
		text := value.String()
		for _, canary := range canaries {
			if strings.Contains(text, canary) {
				*found = append(*found, path+"="+text)
			}
		}
	}
}

// ax02WalkerProbe is one value that exercises every branch the sweep relies on:
// a string, a []byte, a byte array, a slice of interfaces, a non-byte array, a
// map value, a map key and a pointer.
func ax02WalkerProbe() any {
	type child struct{ Text string }
	return struct {
		Text   string
		Raw    []byte
		Fixed  [8]byte
		Any    []any
		FixedS [1]string
		Values map[string]string
		Keys   map[string]string
		Child  *child
	}{
		Text:   "AX02PROBE-STRING",
		Raw:    []byte("AX02PROBE-BYTES"),
		Fixed:  [8]byte{'A', 'X', '0', '2', 'P', 'R', 'B', 'A'},
		Any:    []any{"AX02PROBE-ANY"},
		FixedS: [1]string{"AX02PROBE-ARRAY"},
		Values: map[string]string{"k": "AX02PROBE-MAPVALUE"},
		Keys:   map[string]string{"AX02PROBE-MAPKEY": "v"},
		Child:  &child{Text: "AX02PROBE-POINTER"},
	}
}

// ax02RouteLeaks reports every canary the decoded representation of one request
// route carries: the address as sent, its path, and the decoded keys and values
// of its query. A canary may travel percent-encoded (%41X02CANARY-…), so the
// representation as sent is not the only place to look.
func ax02RouteLeaks(address string, canaries []string) ([]string, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, err
	}
	candidates := []string{address, parsed.Path}
	for key, values := range query {
		candidates = append(candidates, key)
		candidates = append(candidates, values...)
	}
	found := []string{}
	for _, candidate := range candidates {
		for _, canary := range canaries {
			if strings.Contains(candidate, canary) {
				found = append(found, candidate)
			}
		}
	}
	return found, nil
}

// TestAX02DiscardedAPIFieldsNeverReachPublishedArtefacts runs one real
// acquisition over a response whose discarded locations all carry a canary and
// sweeps every published surface of the run.
func TestAX02DiscardedAPIFieldsNeverReachPublishedArtefacts(t *testing.T) {
	// The oracle is not blind: each branch the sweep relies on finds its own
	// synthetic canary. Without these controls a broken walker would pass the
	// whole sweep.
	probe := ax02WalkerProbe()
	for _, canary := range []string{
		"AX02PROBE-STRING", "AX02PROBE-BYTES", "AX02PRBA", "AX02PROBE-ANY",
		"AX02PROBE-ARRAY", "AX02PROBE-MAPVALUE", "AX02PROBE-MAPKEY",
		"AX02PROBE-POINTER",
	} {
		if leaks := ax02Leaks(probe, []string{canary}); len(leaks) == 0 {
			t.Fatalf("the walker misses the branch that carries %q", canary)
		}
	}
	// The route sweep is not blind to an encoded value either: the decoded query
	// is inspected, not only the representation as sent. The last byte of the
	// canary travels percent-encoded, so only the decoded form carries it.
	encoded := "https://synthetic.example:6443/api/v1/namespaces/payments/pods?continue=" +
		strings.TrimSuffix(ax02Env, "v") + "%76"
	encodedLeaks, err := ax02RouteLeaks(encoded, ax02Canaries)
	if err != nil {
		t.Fatalf("the route control is unparseable: %v", err)
	}
	if len(encodedLeaks) == 0 {
		t.Fatal("the route sweep misses a percent-encoded discarded value")
	}
	raw := ax02ListDocument()
	if leaks := ax02Leaks(raw, ax02Canaries); len(leaks) == 0 {
		t.Fatal("the canary walker found nothing in the raw response that carries every canary")
	}
	for _, canary := range ax02Canaries {
		if !strings.Contains(raw, canary) {
			t.Fatalf("the fixture does not place canary %q anywhere", canary)
		}
	}

	transport := newA202ScriptedTransport(
		a202JSONResponse(ax02ListDocument()),
		a202JSONResponse(ax02PodDocument()),
		a202JSONResponse(ax02PodDocument()),
	)
	clock := newA202Clock(t, a202StartMoment)
	clock.advance(time.Second)
	result, err := collectWithDependencies(context.Background(), a202Config(t), transport, clock)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if result.Acquisition.Termination != contract.TerminationFinished {
		t.Fatalf("termination = %q, want a finished run", result.Acquisition.Termination)
	}
	if len(result.Acquisition.Captures) == 0 || len(result.Bundles) == 0 {
		t.Fatalf("the run published no capture (%d) or no bundle (%d)",
			len(result.Acquisition.Captures), len(result.Bundles))
	}

	// 1. The sanitized sources the run publishes.
	for _, capture := range result.Acquisition.Captures {
		for _, canary := range ax02Canaries {
			if bytes.Contains(capture.Bytes, []byte(canary)) {
				t.Fatalf("capture %s carries the discarded value %q", capture.Alias, canary)
			}
		}
	}
	// 2. Every artefact of every built bundle.
	for _, candidate := range result.Bundles {
		encoded, err := bundle.Encode(candidate.Bundle)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		for name, artefact := range map[string]string{
			"envelope":        string(encoded.Envelope),
			"hash projection": string(encoded.HashInput),
			"digest":          encoded.Hash,
		} {
			for _, canary := range ax02Canaries {
				if strings.Contains(artefact, canary) {
					t.Fatalf("the %s carries the discarded value %q", name, canary)
				}
			}
		}
	}
	// 3. The whole published record, field by field.
	if leaks := ax02Leaks(result, ax02Canaries); len(leaks) > 0 {
		t.Fatalf("the published record carries discarded values at %v", leaks)
	}
	// 4. The routes: only Pods of the allowlisted namespace are ever addressed,
	// and no request carries a discarded value anywhere (path or query).
	urls := transport.requestURLs()
	if len(urls) == 0 {
		t.Fatal("the run issued no request")
	}
	for _, address := range urls {
		parsed, err := url.Parse(address)
		if err != nil {
			t.Fatalf("the run issued an unparseable route %q: %v", address, err)
		}
		if parsed.Scheme != "https" || parsed.Host != "synthetic.example:6443" {
			t.Fatalf("the run addressed another authority: %s", address)
		}
		leaks, err := ax02RouteLeaks(address, ax02Canaries)
		if err != nil {
			t.Fatalf("the run issued an unparseable route %q: %v", address, err)
		}
		if len(leaks) > 0 {
			t.Fatalf("the route carries the discarded value in %q: %s", leaks[0], address)
		}
		// Exactly api/v1/namespaces/<allowlisted>/pods[/<name>], never a longer
		// path and never a resource of another name.
		segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
		if len(segments) < 5 || len(segments) > 6 {
			t.Fatalf("the run addressed a path outside the profile: %s", address)
		}
		want := []string{"api", "v1", "namespaces", a202Namespace, "pods"}
		for index, literal := range want {
			if segments[index] != literal {
				t.Fatalf("the run addressed a path outside the profile: %s", address)
			}
		}
		if len(segments) == 6 && segments[5] == "" {
			t.Fatalf("the run addressed an empty pod name: %s", address)
		}
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			t.Fatalf("the run sent an unparseable query %q: %v", parsed.RawQuery, err)
		}
		for key := range query {
			if key != "limit" && key != "continue" {
				t.Fatalf("the run sent an unexpected query key %q: %s", key, address)
			}
		}
	}
	// 5. The positive control: the admitted facts do survive — in the sanitized
	// source and in the bundle envelope — so the sweep is not green because the
	// run published nothing.
	presence := string(result.Acquisition.Captures[0].Bytes)
	for _, admitted := range []string{"u1", "n1", a202Image, a202ImageID, a202Namespace} {
		if !strings.Contains(presence, admitted) {
			t.Fatalf("the admitted value %q did not survive in the sanitized source", admitted)
		}
	}
	envelope, err := bundle.Encode(result.Bundles[0].Bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, admitted := range []string{"u1", "n1", a202Namespace, a202Image, a202ImageID} {
		if !strings.Contains(string(envelope.Envelope), admitted) {
			t.Fatalf("the admitted value %q did not survive in the bundle envelope", admitted)
		}
	}
}
