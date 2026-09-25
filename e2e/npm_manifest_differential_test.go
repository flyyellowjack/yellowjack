//go:build e2e

package e2e

// Tier 3 for issue #122: the version check must agree with npm's EXTRACTOR, not merely
// be reasonable about tarballs.
//
// The check in npmversion.go compares the version a tarball is served as with the version
// inside it. It read the FIRST top-level package.json and matched entry names by stripping
// a "./" prefix. A real npm does neither: it drops the first path component whatever it is
// called, and it writes entries in order so the LAST manifest is what lands in
// node_modules. Both differences were measured against `npm install`, and both let a
// tarball declaring 9.9.9 reach a developer under a 1.0.0 URL -- one of them while the
// firewall logged "version verified: 1.0.0".
//
// Every leg here runs a real npm against a registry serving the crafted bytes with a
// correct dist.integrity, so npm's own integrity check passes and the gate is the only
// thing that can object. The truthful legs run FIRST and are not decoration: if npm could
// not install these layouts at all, the refusals would prove nothing.

import (
	"strings"
	"testing"
)

func TestNpmManifestLayoutsThatDisagreeWithAFirstMatchReader(t *testing.T) {
	bin := buildFirewall(t)

	// Each case is a pair: the same layout, once telling the truth and once lying. The
	// truthful leg is the vacuity guard -- it proves npm installs this layout through the
	// gate, so the lying leg's failure is the refusal and not the layout.
	for _, tc := range []struct {
		name  string
		build func(declared string) []vcFile
		// wantLog appears in the firewall log on the LYING leg only.
		wantLog string
	}{
		{
			name: "two manifests, the lie last",
			build: func(declared string) []vcFile {
				return []vcFile{
					{"package/package.json", versionCheckManifest(versionCheckServed)},
					{"package/index.js", "module.exports = 'yj';\n"},
					{"package/package.json", versionCheckManifest(declared)},
				}
			},
			wantLog: "carries 2 package.json entries",
		},
		{
			// #47, measured 2026-09-23: npm SKIPS link entries, so a symlink NAMED
			// package.json after the real manifest changes nothing npm installs. A reader
			// that counted it failed to read it and served the tarball unchecked.
			name: "a real manifest, then a symlink named package.json",
			build: func(declared string) []vcFile {
				return []vcFile{
					{"package/package.json", versionCheckManifest(declared)},
					{"package/index.js", "module.exports = 'yj';\n"},
					{vcSymlinkPrefix + "package/package.json", "index.js"},
				}
			},
			wantLog: "declares version",
		},
		{
			name: "manifest at the archive root behind ./",
			build: func(declared string) []vcFile {
				return []vcFile{
					{"./package.json", versionCheckManifest(declared)},
					{"./index.js", "module.exports = 'yj';\n"},
				}
			},
			wantLog: "declares version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("control: the same layout telling the truth installs through the gate", func(t *testing.T) {
				reg := startVersionCheckRegistryTgz(t, versionCheckTgzFiles(t, tc.build(versionCheckServed)...))
				fw := startFirewall(t, bin, versionCheckEnv(reg))
				defer fw.stop()
				code, out := runNpmInstall(t, fw.port, versionCheckPkg)
				if code != 0 {
					t.Fatalf("npm could not install a TRUTHFUL tarball in this layout (exit %d) -- npm does "+
						"not accept the layout at all, so a refusal in the next leg would prove nothing "+
						"about the check\n%s\n--- firewall ---\n%s", code, tail(out, 25), tail(fw.log.String(), 40))
				}
				if !strings.Contains(fw.log.String(), "version verified: "+versionCheckServed) {
					t.Fatalf("npm installed the package but the firewall never verified a version -- either the "+
						"bytes did not come through the gate, or the reader still cannot see this layout, "+
						"which is the bug\n--- firewall ---\n%s", tail(fw.log.String(), 40))
				}
			})

			t.Run("the same layout declaring another version is refused", func(t *testing.T) {
				const declared = "9.9.9"
				reg := startVersionCheckRegistryTgz(t, versionCheckTgzFiles(t, tc.build(declared)...))
				fw := startFirewall(t, bin, versionCheckEnv(reg))
				defer fw.stop()
				code, out := runNpmInstall(t, fw.port, versionCheckPkg)
				if code == 0 {
					t.Fatalf("npm INSTALLED a tarball declaring %s under a %s URL -- the misrepresentation "+
						"reached node_modules past the check that exists to stop it\n%s\n--- firewall ---\n%s",
						declared, versionCheckServed, tail(out, 25), logAround(fw.log.String(), 30, "artifact", "refused"))
				}
				if !strings.Contains(out, blockedMarker) {
					t.Errorf("npm failed (exit %d) but its output never shows the block marker, so the "+
						"developer cannot tell a refusal from a broken registry (#20)\n%s", code, tail(out, 30))
				}
				for _, want := range []string{"declares version " + declared, "served as version " + versionCheckServed} {
					if !strings.Contains(out, want) {
						t.Errorf("the developer was never told %q\n%s", want, tail(out, 30))
					}
				}
				if !strings.Contains(fw.log.String(), tc.wantLog) {
					t.Errorf("the operator's log never says %q, so the refusal is not legible as this "+
						"layout's:\n%s", tc.wantLog, tail(fw.log.String(), 40))
				}
				// The failure mode being regressed: serving the bytes while announcing success.
				if strings.Contains(fw.log.String(), "version verified: "+versionCheckServed) {
					t.Errorf("the firewall logged VERIFIED for a tarball declaring %s -- this is the #122 "+
						"bug exactly\n%s", declared, tail(fw.log.String(), 40))
				}
			})
		})
	}
}
