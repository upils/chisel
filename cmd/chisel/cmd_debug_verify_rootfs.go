package main

import (
	"errors"
	"fmt"

	"github.com/jessevdk/go-flags"

	"github.com/canonical/chisel/internal/manifestutil"
)

var shortVerifyRootfsHelp = "Verify an existing rootfs against its manifest"

var longVerifyRootfsHelp = `
The verify-rootfs command validates an existing rootfs filesystem against its
embedded manifest to ensure filesystem integrity.

The command performs comprehensive verification including:
- File existence and type (regular files, directories, symlinks)
- File permissions and modes
- File content integrity (SHA256 hashes)
- Symlink targets
- Hard link consistency
- Manifest structural validity

The verification will check all paths listed in the manifest and report any
inconsistencies found. Files not managed by chisel (not in the manifest) are
not checked.
`

var verifyRootfsDescs = map[string]string{
	"release": "Chisel release name or directory (e.g. ubuntu-22.04)",
	"root":    "Root directory of the rootfs to verify",
}

type cmdDebugVerifyRootfs struct {
	Release string `long:"release" value-name:"<branch|dir>" required:"yes"`
	RootDir string `long:"root" value-name:"<path>" required:"yes"`
}

func init() {
	addDebugCommand("verify-rootfs", shortVerifyRootfsHelp, longVerifyRootfsHelp,
		func() flags.Commander { return &cmdDebugVerifyRootfs{} },
		verifyRootfsDescs, nil)
}

func (cmd *cmdDebugVerifyRootfs) Execute(args []string) error {
	if len(args) > 0 {
		return ErrExtraArgs
	}

	logf("Verifying rootfs at %s...", cmd.RootDir)

	release, err := obtainRelease(cmd.Release)
	if err != nil {
		return err
	}

	mfest, err := manifestutil.RootFSManifest(release, cmd.RootDir)
	if err != nil {
		// Count and report individual errors if it's a joined error
		var joinedErr interface{ Unwrap() []error }
		if errors.As(err, &joinedErr) {
			unwrappedErrors := joinedErr.Unwrap()
			logf("Verification failed with %d error(s):", len(unwrappedErrors))
			for i, e := range unwrappedErrors {
				logf("  %d. %v", i+1, e)
			}
			return fmt.Errorf("rootfs verification failed: found %d inconsistenc(ies)", len(unwrappedErrors))
		}
		return fmt.Errorf("rootfs verification failed: %w", err)
	}

	if mfest == nil {
		return fmt.Errorf("no manifest found in release %q", cmd.Release)
	}

	logf("Verification successful!")
	return nil
}
