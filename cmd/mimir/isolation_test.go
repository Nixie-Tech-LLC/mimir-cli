package main

import "testing"

func TestParseCPUm(t *testing.T) {
	cases := map[string]int64{"": 0, "16": 16000, "500m": 500, "2": 2000, "250m": 250}
	for in, want := range cases {
		if got := parseCPUm(in); got != want {
			t.Errorf("parseCPUm(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseMemMi(t *testing.T) {
	cases := map[string]int64{"": 0, "512Mi": 512, "20Gi": 20480, "1Ti": 1048576, "1048576Ki": 1024}
	for in, want := range cases {
		if got := parseMemMi(in); got != want {
			t.Errorf("parseMemMi(%q) = %d, want %d", in, got, want)
		}
	}
}

// synthetic cluster: a GPU quota fences `thunder`; a pod in `arc-runners` illegally claims a GPU.
func newTestState() *clusterState {
	q := resourceQuota{}
	q.Metadata.Namespace = "thunder"
	q.Spec.Hard = map[string]string{"requests.nvidia.com/gpu": "0"}
	leak := pod{}
	leak.Metadata.Namespace, leak.Metadata.Name = "arc-runners", "ci-x"
	leak.Spec.Containers = []struct {
		Resources struct {
			Requests map[string]string `json:"requests"`
			Limits   map[string]string `json:"limits"`
		} `json:"resources"`
	}{{}}
	leak.Spec.Containers[0].Resources.Requests = map[string]string{"nvidia.com/gpu": "1"}
	media := pod{}
	media.Metadata.Namespace, media.Metadata.Name = "media-stack", "jellyfin"
	media.Spec.Containers = leak.Spec.Containers // also requests a GPU — but legitimately

	return &clusterState{
		quotaByNS: map[string][]resourceQuota{"thunder": {q}},
		pods:      []pod{leak, media},
	}
}

func TestNsFenced(t *testing.T) {
	s := newTestState()
	if !s.nsFenced("thunder") {
		t.Error("thunder should be GPU-fenced")
	}
	if s.nsFenced("media-stack") {
		t.Error("media-stack must not read as fenced")
	}
}

func TestGpuPodsOutside(t *testing.T) {
	s := newTestState()
	// Allowlist model: with media-stack allowlisted, only the arc-runners claim leaks.
	leaks := s.gpuPodsOutside(map[string]bool{"media-stack": true})
	if len(leaks) != 1 || leaks[0] != "arc-runners/ci-x" {
		t.Errorf("gpuPodsOutside = %v, want [arc-runners/ci-x] (allowlisted namespace's GPU pod is allowed)", leaks)
	}
	// Empty allowlist = the card is reserved: EVERY claim is a violation.
	if leaks := s.gpuPodsOutside(nil); len(leaks) != 2 {
		t.Errorf("gpuPodsOutside(nil) = %v, want both claims flagged (card reserved)", leaks)
	}
}
