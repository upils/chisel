package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"time"

	"github.com/jessevdk/go-flags"

	"github.com/canonical/chisel/internal/apacheutil"
	"github.com/canonical/chisel/internal/archive"
	"github.com/canonical/chisel/internal/cache"
	"github.com/canonical/chisel/internal/manifestutil"
	"github.com/canonical/chisel/internal/setup"
	"github.com/canonical/chisel/internal/slicer"
	"github.com/canonical/chisel/public/manifest"
)

var shortCutHelp = "Cut a tree with selected slices"
var longCutHelp = `
The cut command uses the provided selection of package slices
to create a new filesystem tree in the root location.

By default it fetches the slices for the same Ubuntu version as the
current host, unless the --release flag is used.
`

var cutDescs = map[string]string{
	"release": "Chisel release name or directory (e.g. ubuntu-22.04)",
	"root":    "Root for generated content",
	"arch":    "Package architecture",
	"ignore":  "Conditions to ignore (e.g. unmaintained, unstable)",
}

type cmdCut struct {
	Release string   `long:"release" value-name:"<dir>"`
	RootDir string   `long:"root" value-name:"<dir>" required:"yes"`
	Arch    string   `long:"arch" value-name:"<arch>"`
	Ignore  []string `long:"ignore" choice:"unmaintained" choice:"unstable" value-name:"<cond>"`

	Positional struct {
		SliceRefs []string `positional-arg-name:"<slice names>" required:"yes"`
	} `positional-args:"yes"`
}

func init() {
	addCommand("cut", shortCutHelp, longCutHelp, func() flags.Commander { return &cmdCut{} }, cutDescs, nil)
}

func (cmd *cmdCut) Execute(args []string) error {
	if len(args) > 0 {
		return ErrExtraArgs
	}

	sliceKeys := make([]setup.SliceKey, len(cmd.Positional.SliceRefs))
	for i, sliceRef := range cmd.Positional.SliceRefs {
		sliceKey, err := setup.ParseSliceKey(sliceRef)
		if err != nil {
			return err
		}
		sliceKeys[i] = sliceKey
	}

	release, err := obtainRelease(cmd.Release)
	if err != nil {
		return err
	}

	if time.Now().Before(release.Maintenance.Standard) {
		if slices.Contains(cmd.Ignore, "unstable") {
			logf(`Warning: This release is in the "unstable" maintenance status. ` +
				`See https://documentation.ubuntu.com/chisel/en/latest/reference/chisel-releases/chisel.yaml/#maintenance to be safe`)
		} else {
			return fmt.Errorf(`this release is in the "unstable" maintenance status, ` +
				`see https://documentation.ubuntu.com/chisel/en/latest/reference/chisel-releases/chisel.yaml/#maintenance for details`)
		}
	}

	previousSliceKeys, err := recut(release, cmd.RootDir)
	if err != nil {
		return err
	}
	// Merge with explicitly requested slice keys
	for _, s := range previousSliceKeys {
		if !slices.Contains(sliceKeys, s) {
			sliceKeys = append(sliceKeys, s)
		}
	}

	selection, err := setup.Select(release, sliceKeys, cmd.Arch)
	if err != nil {
		return err
	}

	archives := make(map[string]archive.Archive)
	for archiveName, archiveInfo := range release.Archives {
		openArchive, err := archive.Open(&archive.Options{
			Label:      archiveName,
			Version:    archiveInfo.Version,
			Arch:       cmd.Arch,
			Suites:     archiveInfo.Suites,
			Components: archiveInfo.Components,
			Pro:        archiveInfo.Pro,
			CacheDir:   cache.DefaultDir("chisel"),
			PubKeys:    archiveInfo.PubKeys,
			Maintained: archiveInfo.Maintained,
			OldRelease: archiveInfo.OldRelease,
		})
		if err != nil {
			if err == archive.ErrCredentialsNotFound {
				logf("Archive %q ignored: credentials not found", archiveName)
				continue
			}
			return err
		}
		archives[archiveName] = openArchive
	}

	hasMaintainedArchive := false
	for _, archive := range archives {
		if archive.Options().Maintained {
			hasMaintainedArchive = true
			break
		}
	}
	if !hasMaintainedArchive {
		if slices.Contains(cmd.Ignore, "unmaintained") {
			logf(`Warning: No archive has "maintained" maintenance status. ` +
				`Consider the different Ubuntu Pro subscriptions to be safe. ` +
				`See https://documentation.ubuntu.com/chisel/en/latest/reference/chisel-releases/chisel.yaml/#maintenance for details.`)
		} else {
			return fmt.Errorf(`no archive has "maintained" maintenance status, ` +
				`consider the different Ubuntu Pro subscriptions to be safe, ` +
				`see https://documentation.ubuntu.com/chisel/en/latest/reference/chisel-releases/chisel.yaml/#maintenance for details`)
		}
	}

	err = slicer.Run(&slicer.RunOptions{
		Selection: selection,
		Archives:  archives,
		TargetDir: cmd.RootDir,
	})
	return err
}

func recut(release *setup.Release, rootdir string) ([]setup.SliceKey, error) {
	manifests := manifestutil.FindPathsInRelease(release)

	if len(manifests) == 0 {
		// TODO: When enabling the feature, error out if no manifest found.
		// For now do nothing.
		return nil, nil
	}

	// Get targetDir path
	targetDir := filepath.Clean(rootdir)
	if !filepath.IsAbs(targetDir) {
		dir, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("cannot obtain current directory: %w", err)
		}
		targetDir = filepath.Join(dir, targetDir)
	}

	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read root directory %q: %v", targetDir, err)
	}

	if len(entries) == 0 {
		// Empty dir, so cutting a new rootfs
		return nil, nil
	}

	// Root dir is not empty, cutting on top of an existing rootfs.
	
	// Select the first manifest of the list as the reference one for now.
	// Another heuristic could be used (ex. select the one from base-files_chisel).
	firstManifestPath := path.Join(targetDir, manifests[0])
	firstManifest, err := manifestutil.Read(firstManifestPath)
	if err != nil {
		logf("Warning: Cannot read manifest %q from the root directory: %v", firstManifestPath, err)
		return nil, nil
	}
	
	err = manifestutil.CheckManifests(firstManifestPath, targetDir, manifests[1:])
	if err != nil {
		// TODO: When enabling the feature, error out.
		logf("Warning: %v", err)
		return nil, nil
	}
	
	// TODO
	// validate given target rootdir with manifest content

	// Get slices used to build the rootfs
	sliceKeys := []setup.SliceKey{}
	firstManifest.IterateSlices("", func(slice *manifest.Slice) error {
		sk, err := apacheutil.ParseSliceKey(slice.Name)
		if err != nil {
			return err
		}
		sliceKeys = append(sliceKeys, sk)
		return nil
	})

	return sliceKeys, nil
}
