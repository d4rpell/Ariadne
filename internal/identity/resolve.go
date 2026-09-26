package identity

import (
	"errors"
	"fmt"
	"reflect"
)

// Resolve applies the conservative rules to a set of bindings. Bindings are
// grouped by the full ContainerKey (uid + class + name), never by namespace/name
// and never by container name alone. Repeated bindings for the same key are
// accepted only when they describe the same observation; this permits one
// container observation to support multiple findings without choosing between
// sources. Any discrepancy remains a visible conflict.
// The returned resolutions are always non-nil, so a caller that ignores the
// error still receives nothing affirmative.
func Resolve(bindings []ImageBinding) ([]Resolution, error) {
	order := make([]ContainerKey, 0, len(bindings))
	grouped := make(map[ContainerKey][]int, len(bindings))
	for i, binding := range bindings {
		if _, seen := grouped[binding.Key]; !seen {
			order = append(order, binding.Key)
		}
		grouped[binding.Key] = append(grouped[binding.Key], i)
	}

	resolutions := make([]Resolution, 0, len(order))
	var problems []error
	for _, key := range order {
		indexes := grouped[key]
		if len(indexes) == 1 {
			resolution, err := ResolveOne(bindings[indexes[0]])
			if err != nil {
				problems = append(problems, err)
			}
			resolutions = append(resolutions, resolution)
			continue
		}
		if equivalentObservation(bindings, indexes) {
			resolution, err := repeatedResolution(bindings, indexes)
			if err != nil {
				problems = append(problems, err)
			}
			resolutions = append(resolutions, resolution)
			continue
		}
		resolutions = append(resolutions, Resolution{
			Key:          key,
			State:        ResolutionUnknown,
			BindingCount: len(indexes),
			ConflictCode: ConflictSourceConflict,
		})
		problems = append(problems, fmt.Errorf("%w: %s: %d observations", errBindingConflict, ConflictSourceConflict, len(indexes)))
	}
	return resolutions, errors.Join(problems...)
}

func repeatedResolution(bindings []ImageBinding, indexes []int) (Resolution, error) {
	resolution, err := ResolveOne(bindings[indexes[0]])
	if err != nil {
		return resolution, err
	}
	for _, index := range indexes[1:] {
		candidate, candidateErr := ResolveOne(bindings[index])
		if candidateErr != nil {
			resolution.State = ResolutionUnknown
			resolution.Binding = nil
			return resolution, candidateErr
		}
		if resolution.State != candidate.State {
			resolution.State = ResolutionUnknown
			resolution.Binding = nil
			return resolution, fmt.Errorf("%w: repeated observation has inconsistent validation", errBindingConflict)
		}
	}
	resolution.BindingCount = len(indexes)
	return resolution, nil
}

func equivalentObservation(bindings []ImageBinding, indexes []int) bool {
	if len(indexes) < 2 {
		return true
	}
	baseline := bindings[indexes[0]]
	for _, index := range indexes[1:] {
		candidate := bindings[index]
		if baseline.Key != candidate.Key ||
			baseline.InputKind != candidate.InputKind ||
			baseline.SourceName != candidate.SourceName ||
			baseline.SourceHash != candidate.SourceHash ||
			baseline.Locator != candidate.Locator ||
			baseline.Platform != candidate.Platform ||
			baseline.PlatformOS != candidate.PlatformOS ||
			baseline.PlatformArchitecture != candidate.PlatformArchitecture ||
			!reflect.DeepEqual(baseline.RawImageID, candidate.RawImageID) ||
			!reflect.DeepEqual(baseline.GuaranteedDigest, candidate.GuaranteedDigest) ||
			!reflect.DeepEqual(baseline.ObservedAt, candidate.ObservedAt) {
			return false
		}
	}
	return true
}
