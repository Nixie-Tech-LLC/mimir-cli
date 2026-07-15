package main

import "testing"

// requireConfig must not demand an OIDC issuer in --access mode: there the Cloudflare Access JWT is the
// k8s bearer (see validToken/k8sReq), so `mimir projects *` only needs a server. This regression made
// projects list/create/delete fail with "not configured" for remote (Access) users even after login.
func TestRequireConfig(t *testing.T) {
	cases := []struct {
		name       string
		cfg        Config
		needServer bool
		wantErr    bool
	}{
		// --- Access mode: OIDC issuer is irrelevant ---
		{"access, server only, needServer", Config{Access: true, Server: "https://k8s.example"}, true, false},
		{"access, no issuer, no server needed", Config{Access: true}, false, false},
		{"access, needServer but no server", Config{Access: true}, true, true},
		{"access, server set, issuer empty", Config{Access: true, Server: "https://k8s.example", OIDCIssuer: ""}, true, false},

		// --- Dex/OIDC mode: issuer is required, server gated on needServer ---
		{"oidc, issuer+server", Config{OIDCIssuer: "https://dex.example", Server: "https://k8s.example"}, true, false},
		{"oidc, issuer only, no server needed", Config{OIDCIssuer: "https://dex.example"}, false, false},
		{"oidc, issuer only, server needed", Config{OIDCIssuer: "https://dex.example"}, true, true},
		{"oidc, no issuer", Config{Server: "https://k8s.example"}, true, true},
		{"oidc, nothing set", Config{}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.requireConfig(tc.needServer)
			if (err != nil) != tc.wantErr {
				t.Errorf("requireConfig(needServer=%v) err = %v, wantErr = %v", tc.needServer, err, tc.wantErr)
			}
		})
	}
}
