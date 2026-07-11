// mimir — a gcloud-style CLI for the mimir platform. Self-contained (stdlib only): implements the OIDC
// device flow (RFC 8628) against Dex, caches/refreshes tokens, serves as its own kubeconfig exec-credential,
// and talks to the k8s API over REST. No kubectl/kubelogin required.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// version is injected at build time via -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Config is ~/.mimir/config.json; every field is overridable by env (see loadConfig).
type Config struct {
	Server       string `json:"server"`       // apiserver URL, e.g. https://apiserver-host:6443
	ServerCA     string `json:"serverCA"`     // PEM that signs the apiserver cert
	OIDCIssuer   string `json:"oidcIssuer"`   // Dex issuer URL, e.g. https://dex-issuer-host
	OIDCClientID string `json:"oidcClientID"` // mimir-cli
	OIDCCA       string `json:"oidcCA"`       // PEM that signs Dex's cert (mimir-ca)
	Insecure     bool   `json:"insecure"`     // skip TLS verify (dev only)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "auth":
		err = authCmd(os.Args[2:])
	case "projects", "project":
		err = projectsCmd(os.Args[2:])
	case "configure":
		err = configureCmd(os.Args[2:])
	case "iam":
		err = fmt.Errorf("`mimir iam` account provisioning is a platform-admin path (Thunder); not yet exposed")
	case "version", "--version", "-v":
		fmt.Printf("mimir %s (commit %s, built %s, %s/%s)\n", version, commit, date, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`mimir — the mimir platform CLI (gcloud-style)

  mimir auth login                 Log in via Dex device flow; cache the token
  mimir auth get-token             Print an ExecCredential (used by kubeconfig; auto-refreshes)
  mimir auth whoami                Show your identity + groups from the token
  mimir auth logout                Delete the cached token
  mimir projects create NAME [--member EMAIL ...] [--cpu 4] [--memory 8Gi] [--pods 20]
  mimir projects list
  mimir projects delete NAME
  mimir configure [--server URL] [--server-ca FILE] [--oidc-issuer URL] [--oidc-client-id ID] [--oidc-ca FILE] [--insecure]
  mimir version

Config: ~/.mimir/config.json (or env MIMIR_SERVER, MIMIR_SERVER_CA_FILE, MIMIR_OIDC_ISSUER,
        MIMIR_OIDC_CLIENT_ID, MIMIR_OIDC_CA_FILE, MIMIR_INSECURE=1).
`)
}

// ---- config -----------------------------------------------------------------

func mimirDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".mimir")
}

func loadConfig() Config {
	// No deployment-specific defaults are baked into the binary (a client shouldn't hardcode one cluster's
	// topology). Endpoints come from `mimir configure` / ~/.mimir/config.json / env. Only the generic OAuth
	// client id has a default.
	c := Config{OIDCClientID: "mimir-cli"}
	if b, err := os.ReadFile(filepath.Join(mimirDir(), "config.json")); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if v := os.Getenv("MIMIR_SERVER"); v != "" {
		c.Server = v
	}
	if v := os.Getenv("MIMIR_OIDC_ISSUER"); v != "" {
		c.OIDCIssuer = v
	}
	if v := os.Getenv("MIMIR_OIDC_CLIENT_ID"); v != "" {
		c.OIDCClientID = v
	}
	if v := os.Getenv("MIMIR_OIDC_CA_FILE"); v != "" {
		if b, err := os.ReadFile(v); err == nil {
			c.OIDCCA = string(b)
		}
	}
	if v := os.Getenv("MIMIR_SERVER_CA_FILE"); v != "" {
		if b, err := os.ReadFile(v); err == nil {
			c.ServerCA = string(b)
		}
	}
	if os.Getenv("MIMIR_INSECURE") == "1" {
		c.Insecure = true
	}
	return c
}

func configureCmd(args []string) error {
	c := loadConfig()
	for i := 0; i < len(args); i++ {
		next := func() string { i++; return args[i] }
		switch args[i] {
		case "--server":
			c.Server = next()
		case "--oidc-issuer":
			c.OIDCIssuer = next()
		case "--oidc-client-id":
			c.OIDCClientID = next()
		case "--server-ca":
			b, err := os.ReadFile(next())
			if err != nil {
				return err
			}
			c.ServerCA = string(b)
		case "--oidc-ca":
			b, err := os.ReadFile(next())
			if err != nil {
				return err
			}
			c.OIDCCA = string(b)
		case "--insecure":
			c.Insecure = true
		}
	}
	if err := os.MkdirAll(mimirDir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(filepath.Join(mimirDir(), "config.json"), b, 0o600); err != nil {
		return err
	}
	fmt.Println("wrote", filepath.Join(mimirDir(), "config.json"))
	return nil
}

// httpClient builds an HTTP client trusting the given PEM CA (or system roots / insecure).
func httpClient(caPEM string, insecure bool) *http.Client {
	tc := &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // opt-in dev flag
	if caPEM != "" && !insecure {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(caPEM))
		tc.RootCAs = pool
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
}

// ---- OIDC device flow -------------------------------------------------------

type discovery struct {
	DeviceEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint  string `json:"token_endpoint"`
}
type deviceResp struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	VerificationC   string `json:"verification_uri_complete"`
	Interval        int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}
type tokenResp struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}
type tokenCache struct {
	IDToken      string    `json:"id_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

func (c Config) oidc() *http.Client { return httpClient(c.OIDCCA, c.Insecure) }

// requireConfig gives a clear message when the (deliberately un-defaulted) endpoints aren't set yet.
func (c Config) requireConfig(needServer bool) error {
	if c.OIDCIssuer == "" || (needServer && c.Server == "") {
		return fmt.Errorf("not configured — run `mimir configure --server <url> --oidc-issuer <url> " +
			"[--server-ca FILE --oidc-ca FILE]` (or set MIMIR_SERVER / MIMIR_OIDC_ISSUER)")
	}
	return nil
}

func discover(c Config) (discovery, error) {
	var d discovery
	resp, err := c.oidc().Get(strings.TrimRight(c.OIDCIssuer, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	return d, json.NewDecoder(resp.Body).Decode(&d)
}

func authCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mimir auth login|get-token|whoami|logout")
	}
	c := loadConfig()
	switch args[0] {
	case "login":
		return authLogin(c)
	case "get-token":
		return authGetToken(c)
	case "whoami":
		return authWhoami(c)
	case "logout":
		return os.Remove(filepath.Join(mimirDir(), "token.json"))
	}
	return fmt.Errorf("unknown auth subcommand %q", args[0])
}

func authLogin(c Config) error {
	if err := c.requireConfig(false); err != nil {
		return err
	}
	d, err := discover(c)
	if err != nil {
		return fmt.Errorf("discovery failed (issuer %s reachable? CA set?): %w", c.OIDCIssuer, err)
	}
	form := url.Values{"client_id": {c.OIDCClientID}, "scope": {"openid email groups offline_access"}}
	resp, err := c.oidc().PostForm(d.DeviceEndpoint, form)
	if err != nil {
		return err
	}
	var dr deviceResp
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(body, &dr); err != nil || dr.DeviceCode == "" {
		return fmt.Errorf("device authorization failed: %s", strings.TrimSpace(string(body)))
	}
	uri := dr.VerificationC
	if uri == "" {
		uri = dr.VerificationURI + "  (enter code: " + dr.UserCode + ")"
	}
	fmt.Printf("\nTo sign in, open:\n\n    %s\n\n", uri)
	openBrowser(dr.VerificationC)
	interval := dr.Interval
	if interval <= 0 {
		interval = 5
	}
	deadline := time.Now().Add(time.Duration(max(dr.ExpiresIn, 300)) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)
		tr, err := poll(c, d.TokenEndpoint, dr.DeviceCode)
		if err != nil {
			return err
		}
		switch tr.Error {
		case "":
			if err := saveToken(tr); err != nil {
				return err
			}
			fmt.Println("Login successful. Token cached in ~/.mimir/token.json")
			return nil
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5
		default:
			return fmt.Errorf("login failed: %s", tr.Error)
		}
	}
	return fmt.Errorf("device code expired before authorization")
}

func poll(c Config, tokenEndpoint, deviceCode string) (tokenResp, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {c.OIDCClientID},
	}
	var tr tokenResp
	resp, err := c.oidc().PostForm(tokenEndpoint, form)
	if err != nil {
		return tr, err
	}
	defer resp.Body.Close()
	return tr, json.NewDecoder(resp.Body).Decode(&tr)
}

func saveToken(tr tokenResp) error {
	if err := os.MkdirAll(mimirDir(), 0o700); err != nil {
		return err
	}
	tc := tokenCache{IDToken: tr.IDToken, RefreshToken: tr.RefreshToken,
		Expiry: time.Now().Add(time.Duration(max(tr.ExpiresIn, 60)) * time.Second)}
	b, _ := json.MarshalIndent(tc, "", "  ")
	return os.WriteFile(filepath.Join(mimirDir(), "token.json"), b, 0o600)
}

func loadToken() (tokenCache, error) {
	var tc tokenCache
	b, err := os.ReadFile(filepath.Join(mimirDir(), "token.json"))
	if err != nil {
		return tc, fmt.Errorf("not logged in (run `mimir auth login`)")
	}
	return tc, json.Unmarshal(b, &tc)
}

// validToken returns a non-expired id_token, refreshing via refresh_token if needed.
func validToken(c Config) (string, error) {
	tc, err := loadToken()
	if err != nil {
		return "", err
	}
	if time.Now().Before(tc.Expiry.Add(-30 * time.Second)) {
		return tc.IDToken, nil
	}
	if tc.RefreshToken == "" {
		return "", fmt.Errorf("token expired and no refresh token; run `mimir auth login`")
	}
	d, err := discover(c)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tc.RefreshToken}, "client_id": {c.OIDCClientID}}
	resp, err := c.oidc().PostForm(d.TokenEndpoint, form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tr tokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", err
	}
	if tr.IDToken == "" {
		return "", fmt.Errorf("refresh failed (%s); run `mimir auth login`", tr.Error)
	}
	if tr.RefreshToken == "" {
		tr.RefreshToken = tc.RefreshToken
	}
	_ = saveToken(tr)
	return tr.IDToken, nil
}

// authGetToken emits an ExecCredential — kubeconfig users reference `mimir auth get-token`.
func authGetToken(c Config) error {
	tok, err := validToken(c)
	if err != nil {
		return err
	}
	exp := ""
	if _, claims, e := decodeJWT(tok); e == nil {
		if v, ok := claims["exp"].(float64); ok {
			exp = time.Unix(int64(v), 0).UTC().Format(time.RFC3339)
		}
	}
	out := map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1beta1",
		"kind":       "ExecCredential",
		"status":     map[string]any{"token": tok, "expirationTimestamp": exp},
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	return nil
}

func authWhoami(c Config) error {
	tok, err := validToken(c)
	if err != nil {
		return err
	}
	_, claims, err := decodeJWT(tok)
	if err != nil {
		return err
	}
	fmt.Printf("user:   %v\n", claims["email"])
	fmt.Printf("issuer: %v\n", claims["iss"])
	if g, ok := claims["groups"]; ok {
		fmt.Printf("groups: %v\n", g)
	} else {
		fmt.Println("groups: (none)")
	}
	return nil
}

func decodeJWT(tok string) (map[string]any, map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("malformed token")
	}
	dec := func(s string) (map[string]any, error) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		return m, json.Unmarshal(b, &m)
	}
	h, err := dec(parts[0])
	if err != nil {
		return nil, nil, err
	}
	p, err := dec(parts[1])
	return h, p, err
}

func openBrowser(u string) {
	if u == "" {
		return
	}
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", u)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		c = exec.Command("xdg-open", u)
	}
	_ = c.Start()
}

// ---- k8s REST (projects.kro.run) --------------------------------------------

func k8sReq(c Config, method, path string, body []byte) ([]byte, int, error) {
	tok, err := validToken(c)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.Server, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient(c.ServerCA, c.Insecure).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

const projPath = "/apis/kro.run/v1alpha1/projects"

func projectsCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mimir projects create|list|delete")
	}
	c := loadConfig()
	if err := c.requireConfig(true); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		b, code, err := k8sReq(c, "GET", projPath, nil)
		if err != nil {
			return err
		}
		if code >= 300 {
			return apiErr(b, code)
		}
		var l struct {
			Items []struct {
				Metadata struct{ Name string } `json:"metadata"`
				Spec     struct{ DisplayName string } `json:"spec"`
				Status   struct{ State string } `json:"status"`
			} `json:"items"`
		}
		_ = json.Unmarshal(b, &l)
		fmt.Printf("%-24s %-16s %s\n", "NAME", "STATE", "DISPLAY")
		for _, it := range l.Items {
			fmt.Printf("%-24s %-16s %s\n", it.Metadata.Name, it.Status.State, it.Spec.DisplayName)
		}
		return nil
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: mimir projects delete NAME")
		}
		b, code, err := k8sReq(c, "DELETE", projPath+"/"+args[1], nil)
		if err != nil {
			return err
		}
		if code >= 300 {
			return apiErr(b, code)
		}
		fmt.Println("deleted", args[1])
		return nil
	case "create":
		return projectsCreate(c, args[1:])
	}
	return fmt.Errorf("unknown projects subcommand %q", args[0])
}

func projectsCreate(c Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mimir projects create NAME [--member EMAIL ...] [--cpu N] [--memory X] [--pods N]")
	}
	name := args[0]
	cpu, mem, pods := "4", "8Gi", "20"
	var members []string
	for i := 1; i < len(args); i++ {
		next := func() string { i++; return args[i] }
		switch args[i] {
		case "--member":
			members = append(members, "mimir:"+strings.TrimPrefix(next(), "mimir:"))
		case "--cpu":
			cpu = next()
		case "--memory":
			mem = next()
		case "--pods":
			pods = next()
		}
	}
	proj := map[string]any{
		"apiVersion": "kro.run/v1alpha1", "kind": "Project",
		"metadata": map[string]any{"name": name},
		"spec": map[string]any{
			"displayName": name, "members": members,
			"quota": map[string]any{"cpu": cpu, "memory": mem, "pods": pods},
		},
	}
	body, _ := json.Marshal(proj)
	b, code, err := k8sReq(c, "POST", projPath, body)
	if err != nil {
		return err
	}
	if code >= 300 {
		return apiErr(b, code)
	}
	fmt.Printf("project %q created\n", name)
	return nil
}

func apiErr(b []byte, code int) error {
	var s struct{ Message string `json:"message"` }
	_ = json.Unmarshal(b, &s)
	if s.Message != "" {
		return fmt.Errorf("api error %d: %s", code, s.Message)
	}
	return fmt.Errorf("api error %d: %s", code, strings.TrimSpace(string(b)))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
