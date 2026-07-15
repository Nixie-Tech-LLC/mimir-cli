package main

// `mimir isolation` — the entry point for the workload-isolation guardrails that keep media-stack safe from
// noisy neighbours on the shared node. tofu (tofu/isolation) DECLARES + APPLIES the k8s objects; this command
// is the human/CI UX over them:
//   show     read the live cluster and print the budget, the media-stack floor, and any GPU leaks
//   verify   assert the isolation invariants against the live cluster; non-zero exit on breach (CI gate)
//   plan     `tofu plan`  the module (re-proves the floor via its check blocks)
//   apply    `tofu apply` the module
// show/verify talk the k8s REST API with your token (needs cluster read on quotas/limitranges/pods/nodes).

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

func isolationCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mimir isolation show|verify|plan|apply")
	}
	switch args[0] {
	case "show":
		return isolationShow(loadConfig())
	case "verify":
		return isolationVerify(loadConfig(), args[1:])
	case "plan":
		return tofuRun(args[1:], "plan", "-input=false")
	case "apply":
		return tofuRun(args[1:], "apply")
	}
	return fmt.Errorf("unknown isolation subcommand %q", args[0])
}

// ---- tofu passthrough (plan/apply) ------------------------------------------

// tofuRun shells out to `tofu -chdir=<module> <action>` after an init. Module dir: --dir FLAG, else
// $MIMIR_ISOLATION_DIR, else ./tofu/isolation. Extra args after a `--` are forwarded to tofu.
func tofuRun(args []string, action string, extra ...string) error {
	dir := os.Getenv("MIMIR_ISOLATION_DIR")
	if dir == "" {
		dir = "tofu/isolation"
	}
	var passthrough []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			if i+1 >= len(args) {
				return fmt.Errorf("--dir needs a path")
			}
			i++
			dir = args[i]
		case "--":
			passthrough = append(passthrough, args[i+1:]...)
			i = len(args)
		default:
			passthrough = append(passthrough, args[i])
		}
	}
	if _, err := exec.LookPath("tofu"); err != nil {
		return fmt.Errorf("`tofu` not found on PATH — install OpenTofu, or apply via GitOps (tofu-controller)")
	}
	run := func(a ...string) error {
		c := exec.Command("tofu", a...)
		c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
		return c.Run()
	}
	if err := run("-chdir="+dir, "init", "-input=false"); err != nil {
		return fmt.Errorf("tofu init failed: %w", err)
	}
	return run(append(append([]string{"-chdir=" + dir, action}, extra...), passthrough...)...)
}

// ---- live cluster reads -----------------------------------------------------

type resourceQuota struct {
	Metadata struct{ Name, Namespace string } `json:"metadata"`
	Spec     struct {
		Hard map[string]string `json:"hard"`
	} `json:"spec"`
}
type limitRange struct {
	Metadata struct{ Name, Namespace string } `json:"metadata"`
}
type priorityClass struct {
	Metadata      struct{ Name string } `json:"metadata"`
	Value         int64                 `json:"value"`
	GlobalDefault bool                  `json:"globalDefault"`
}
type pod struct {
	Metadata struct{ Name, Namespace string } `json:"metadata"`
	Spec     struct {
		Containers []struct {
			Resources struct {
				Requests map[string]string `json:"requests"`
				Limits   map[string]string `json:"limits"`
			} `json:"resources"`
		} `json:"containers"`
	} `json:"spec"`
}
type node struct {
	Metadata struct{ Name string } `json:"metadata"`
	Status   struct {
		Allocatable map[string]string `json:"allocatable"`
	} `json:"status"`
}

func listK8s[T any](c Config, path string) ([]T, error) {
	b, code, err := k8sReq(c, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, apiErr(b, code)
	}
	var l struct {
		Items []T `json:"items"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	return l.Items, nil
}

// clusterState is everything show/verify need, fetched once.
type clusterState struct {
	quotas    []resourceQuota
	limits    []limitRange
	prios     []priorityClass
	pods      []pod
	nodes     []node
	lrByNS    map[string]bool
	quotaByNS map[string][]resourceQuota
}

func fetchState(c Config) (*clusterState, error) {
	if err := c.requireConfig(true); err != nil {
		return nil, err
	}
	s := &clusterState{lrByNS: map[string]bool{}, quotaByNS: map[string][]resourceQuota{}}
	var err error
	if s.quotas, err = listK8s[resourceQuota](c, "/api/v1/resourcequotas"); err != nil {
		return nil, fmt.Errorf("list resourcequotas: %w", err)
	}
	if s.limits, err = listK8s[limitRange](c, "/api/v1/limitranges"); err != nil {
		return nil, fmt.Errorf("list limitranges: %w", err)
	}
	if s.prios, err = listK8s[priorityClass](c, "/apis/scheduling.k8s.io/v1/priorityclasses"); err != nil {
		return nil, fmt.Errorf("list priorityclasses: %w", err)
	}
	if s.pods, err = listK8s[pod](c, "/api/v1/pods"); err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	if s.nodes, err = listK8s[node](c, "/api/v1/nodes"); err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	for _, lr := range s.limits {
		s.lrByNS[lr.Metadata.Namespace] = true
	}
	for _, q := range s.quotas {
		s.quotaByNS[q.Metadata.Namespace] = append(s.quotaByNS[q.Metadata.Namespace], q)
	}
	return s, nil
}

// gpuPodsOutside returns "ns/pod" for every pod requesting a GPU whose namespace isn't in the allowlist.
// GPU model since 2026-07-14: the card belongs to the gpu_namespaces allowlist (ML) — an empty/nil allowlist
// means the card is reserved and EVERY claim is a violation (media-stack is CPU-only and fenced).
func (s *clusterState) gpuPodsOutside(allowed map[string]bool) []string {
	var out []string
	for _, p := range s.pods {
		if allowed[p.Metadata.Namespace] {
			continue
		}
		for _, ct := range p.Spec.Containers {
			if gpu(ct.Resources.Requests) > 0 || gpu(ct.Resources.Limits) > 0 {
				out = append(out, p.Metadata.Namespace+"/"+p.Metadata.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func gpu(m map[string]string) int64 {
	if v, ok := m["nvidia.com/gpu"]; ok {
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

// nsFenced reports whether a namespace has a quota pinning nvidia.com/gpu to 0.
func (s *clusterState) nsFenced(ns string) bool {
	for _, q := range s.quotaByNS[ns] {
		if v, ok := q.Spec.Hard["requests.nvidia.com/gpu"]; ok && v == "0" {
			return true
		}
	}
	return false
}

// ---- show -------------------------------------------------------------------

func isolationShow(c Config) error {
	s, err := fetchState(c)
	if err != nil {
		return err
	}
	// node allocatable + a live floor estimate (allocatable − Σ requests.cpu across all quotas).
	var allocCPU, allocMem int64
	for _, n := range s.nodes {
		allocCPU += parseCPUm(n.Status.Allocatable["cpu"])
		allocMem += parseMemMi(n.Status.Allocatable["memory"])
	}
	var reqCPU, reqMem int64
	for _, q := range s.quotas {
		reqCPU += parseCPUm(q.Spec.Hard["requests.cpu"])
		reqMem += parseMemMi(q.Spec.Hard["requests.memory"])
	}
	fmt.Printf("node allocatable : %dm cpu / %dMi mem  (%d node[s])\n", allocCPU, allocMem, len(s.nodes))
	fmt.Printf("tenant reserved  : %dm cpu / %dMi mem  (Σ quota requests)\n", reqCPU, reqMem)
	fmt.Printf("media-stack floor: %dm cpu / %dMi mem  (allocatable − reserved)\n\n", allocCPU-reqCPU, allocMem-reqMem)

	fmt.Printf("%-28s %-10s %-8s %-12s %-6s %s\n", "NAMESPACE", "req.cpu", "req.mem", "lim.cpu/mem", "gpu", "limitrange")
	nss := map[string]bool{}
	for ns := range s.quotaByNS {
		nss[ns] = true
	}
	var names []string
	for ns := range nss {
		names = append(names, ns)
	}
	sort.Strings(names)
	for _, ns := range names {
		h := map[string]string{}
		for _, q := range s.quotaByNS[ns] {
			for k, v := range q.Spec.Hard {
				h[k] = v
			}
		}
		gpuv := "—"
		if v, ok := h["requests.nvidia.com/gpu"]; ok {
			gpuv = v
		}
		lr := "MISSING"
		if s.lrByNS[ns] {
			lr = "yes"
		}
		fmt.Printf("%-28s %-10s %-8s %-12s %-6s %s\n", ns,
			dash(h["requests.cpu"]), dash(h["requests.memory"]),
			dash(h["limits.cpu"])+"/"+dash(h["limits.memory"]), gpuv, lr)
	}
	fmt.Println("\npriority classes:")
	for _, pc := range s.prios {
		if strings.HasPrefix(pc.Metadata.Name, "system-") {
			continue
		}
		fmt.Printf("  %-24s value=%-12d globalDefault=%v\n", pc.Metadata.Name, pc.Value, pc.GlobalDefault)
	}
	// show is policy-free, so report claims neutrally — verify (with the policy) judges them.
	if claims := s.gpuPodsOutside(nil); len(claims) > 0 {
		fmt.Printf("\nGPU claims: %s  (allowed set = policy gpu_namespaces; run verify to judge)\n", strings.Join(claims, ", "))
	} else {
		fmt.Println("\nGPU: no pod claims a time-slice (card reserved for gpu_namespaces)")
	}
	return nil
}

// ---- verify (the CI gate) ---------------------------------------------------

func isolationVerify(c Config, args []string) error {
	var policyFile string
	for i := 0; i < len(args); i++ {
		if args[i] == "--policy" && i+1 < len(args) {
			i++
			policyFile = args[i]
		}
	}
	s, err := fetchState(c)
	if err != nil {
		return err
	}
	var pol struct {
		MediaNamespace string   `json:"media_namespace"`
		Capped         []string `json:"capped"`
		GPUFenced      []string `json:"gpu_fenced"`
		GPUNamespaces  []string `json:"gpu_namespaces"` // the card's ONLY allowed consumers (empty = reserved)
		PriorityClass  string   `json:"priority_class"`
	}
	if policyFile != "" {
		b, err := os.ReadFile(policyFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &pol); err != nil {
			return fmt.Errorf("policy %s: %w", policyFile, err)
		}
	}
	if pol.PriorityClass == "" {
		pol.PriorityClass = "media-stack-critical"
	}
	gpuAllowed := map[string]bool{}
	for _, ns := range pol.GPUNamespaces {
		gpuAllowed[ns] = true
	}

	var fails []string
	fail := func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }

	// 1. media PriorityClass exists, positive, not the global default.
	var pc *priorityClass
	for i := range s.prios {
		if s.prios[i].Metadata.Name == pol.PriorityClass {
			pc = &s.prios[i]
		}
	}
	if pc == nil {
		fail("PriorityClass %q missing", pol.PriorityClass)
	} else if pc.Value <= 0 || pc.Value >= 2000000000 {
		fail("PriorityClass %q value %d out of range (1..2e9-1)", pol.PriorityClass, pc.Value)
	} else if pc.GlobalDefault {
		fail("PriorityClass %q is globalDefault — every pod would inherit it", pol.PriorityClass)
	}

	// 2. every namespace whose quota constrains limits.* also has a LimitRange (else pods get rejected).
	for ns, qs := range s.quotaByNS {
		constrains := false
		for _, q := range qs {
			if _, ok := q.Spec.Hard["limits.cpu"]; ok {
				constrains = true
			}
			if _, ok := q.Spec.Hard["limits.memory"]; ok {
				constrains = true
			}
		}
		if constrains && !s.lrByNS[ns] {
			fail("namespace %q has a limits quota but no LimitRange (pods without limits will be rejected)", ns)
		}
	}

	// 3. GPU claims only in the gpu_namespaces allowlist (empty allowlist = card reserved, any claim fails).
	for _, leak := range s.gpuPodsOutside(gpuAllowed) {
		fail("GPU claimed outside gpu_namespaces %v: %s", pol.GPUNamespaces, leak)
	}

	// 4. an allowlisted GPU namespace must not be fenced (a gpu:0 quota would silently defeat the allowlist).
	for _, ns := range pol.GPUNamespaces {
		if s.nsFenced(ns) {
			fail("gpu namespace %q is GPU-fenced — its quota pins nvidia.com/gpu to 0", ns)
		}
	}

	// 5. with a policy: each declared capped ns has quota+limitrange; each fenced ns pins gpu 0.
	for _, ns := range pol.Capped {
		if len(s.quotaByNS[ns]) == 0 {
			fail("capped namespace %q has no ResourceQuota", ns)
		}
		if !s.lrByNS[ns] {
			fail("capped namespace %q has no LimitRange", ns)
		}
	}
	for _, ns := range pol.GPUFenced {
		if !s.nsFenced(ns) {
			fail("namespace %q is not GPU-fenced (expected nvidia.com/gpu: 0 quota)", ns)
		}
	}

	if len(fails) > 0 {
		sort.Strings(fails)
		fmt.Fprintf(os.Stderr, "isolation verify: %d FAILED\n", len(fails))
		for _, f := range fails {
			fmt.Fprintf(os.Stderr, "  ✗ %s\n", f)
		}
		return fmt.Errorf("%d isolation invariant(s) violated", len(fails))
	}
	fmt.Println("isolation verify: all invariants hold ✓")
	return nil
}

// ---- tiny k8s quantity parsers (display/floor only; not a full quantity impl) ------------------------------

func parseCPUm(s string) int64 {
	if s == "" {
		return 0
	}
	if strings.HasSuffix(s, "m") {
		n, _ := strconv.ParseInt(strings.TrimSuffix(s, "m"), 10, 64)
		return n
	}
	f, _ := strconv.ParseFloat(s, 64)
	return int64(f * 1000)
}

// parseMemMi handles the common suffixes k8s emits (Ki/Mi/Gi/Ti and plain bytes).
func parseMemMi(s string) int64 {
	if s == "" {
		return 0
	}
	mult := map[string]float64{"Ki": 1.0 / 1024, "Mi": 1, "Gi": 1024, "Ti": 1024 * 1024}
	for suf, m := range mult {
		if strings.HasSuffix(s, suf) {
			n, _ := strconv.ParseFloat(strings.TrimSuffix(s, suf), 64)
			return int64(n * m)
		}
	}
	n, _ := strconv.ParseFloat(s, 64) // bytes
	return int64(n / (1024 * 1024))
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
