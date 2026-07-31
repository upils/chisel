package setup_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/setup"
)

var channelPatternTests = []struct {
	summary string
	values  []string
	err     string
	// match maps a concrete channel to whether the patterns match it.
	match map[setup.Channel]bool
}{{
	summary: "No pattern matches every channel",
	values:  nil,
	match: map[setup.Channel]bool{
		{"3.0", "stable", ""}: true,
		{"2.0", "edge", ""}:   true,
	},
}, {
	summary: "Precise channel",
	values:  []string{"0.3/stable"},
	match: map[setup.Channel]bool{
		{"0.3", "stable", ""}: true,
		{"0.3", "edge", ""}:   false,
		{"0.2", "stable", ""}: false,
		// Branches are ephemeral, hence never part of a pattern. The entry
		// applies to every branch of the risk it matches.
		{"0.3", "stable", "mybranch"}: true,
		{"0.3", "edge", "mybranch"}:   false,
	},
}, {
	summary: "All risks of a track",
	values:  []string{"0.3/*"},
	match: map[setup.Channel]bool{
		{"0.3", "stable", ""}: true,
		{"0.3", "edge", ""}:   true,
		{"0.2", "stable", ""}: false,
	},
}, {
	summary: "Excluded risk",
	values:  []string{"0.2/!stable"},
	match: map[setup.Channel]bool{
		{"0.2", "stable", ""}: false,
		{"0.2", "edge", ""}:   true,
		{"0.2", "beta", ""}:   true,
		// The exclusion is scoped to its own track, it never means "any
		// other track".
		{"0.3", "edge", ""}: false,
		// The branch is ignored, it must not be taken for part of the risk.
		{"0.2", "stable", "mybranch"}: false,
		{"0.2", "edge", "mybranch"}:   true,
	},
}, {
	summary: "Channel without a risk never matches",
	values:  []string{"0.3/*"},
	match: map[setup.Channel]bool{
		// A channel without a risk is not a channel, it must not match just
		// because the missing risk differs from an excluded one.
		{Track: "0.3"}: false,
		{}:             false,
	},
}, {
	summary: "Several risks",
	values:  []string{"0.2/beta,edge"},
	match: map[setup.Channel]bool{
		{"0.2", "beta", ""}:   true,
		{"0.2", "edge", ""}:   true,
		{"0.2", "stable", ""}: false,
	},
}, {
	summary: "Union of several tracks",
	values:  []string{"0.2/!stable", "0.3/*"},
	match: map[setup.Channel]bool{
		{"0.2", "edge", ""}:   true,
		{"0.2", "stable", ""}: false,
		{"0.3", "stable", ""}: true,
	},
}, {
	summary: "Every known risk",
	values:  []string{"0.3/stable,candidate,beta,edge"},
	match: map[setup.Channel]bool{
		{"0.3", "stable", ""}:    true,
		{"0.3", "candidate", ""}: true,
		{"0.3", "beta", ""}:      true,
		{"0.3", "edge", ""}:      true,
	},
}, {
	summary: "Unknown risk",
	values:  []string{"0.3/whatever"},
	err:     `"0.3/whatever": unknown risk "whatever", must be one of stable, candidate, beta, edge`,
}, {
	summary: "Unknown risk in a list",
	values:  []string{"0.3/edge,whatever"},
	err:     `"0.3/edge,whatever": unknown risk "whatever", must be one of stable, candidate, beta, edge`,
}, {
	summary: "Unknown excluded risk",
	values:  []string{"0.3/!whatever"},
	err:     `"0.3/!whatever": unknown risk "whatever", must be one of stable, candidate, beta, edge`,
}, {
	summary: "Risks are case sensitive",
	values:  []string{"0.3/Stable"},
	err:     `"0.3/Stable": unknown risk "Stable", must be one of stable, candidate, beta, edge`,
}, {
	// A pattern never holds a branch, it applies to every branch of the risks
	// it matches.
	summary: "Pattern holding a branch",
	values:  []string{"0.3/stable/mybranch"},
	err:     `"0.3/stable/mybranch": must be <track>/<risk>`,
}, {
	summary: "Missing risk",
	values:  []string{"0.3"},
	err:     `"0.3": must be <track>/<risk>`,
}, {
	summary: "Empty risk",
	values:  []string{"0.3/"},
	err:     `"0.3/": must be <track>/<risk>`,
}, {
	summary: "Empty track",
	values:  []string{"/stable"},
	err:     `"/stable": must be <track>/<risk>`,
}, {
	summary: "Empty excluded risk",
	values:  []string{"0.3/!"},
	err:     `"0.3/!": must be <track>/<risk>`,
}, {
	summary: "Wildcard track",
	values:  []string{"*/stable"},
	err:     `"\*/stable": only the risk accepts '\*', '!' and ','`,
}, {
	summary: "Partial wildcard in track",
	values:  []string{"0.3-*/stable"},
	err:     `"0.3-\*/stable": only the risk accepts '\*', '!' and ','`,
}, {
	summary: "Wildcard is not a glob",
	values:  []string{"0.3/e*"},
	err:     `"0.3/e\*": '\*' must be the whole risk`,
}, {
	summary: "Exclusion combined with other risks",
	values:  []string{"0.3/!stable,edge"},
	err:     `"0.3/!stable,edge": '!' cannot be combined with other risks`,
}, {
	summary: "Exclusion not prefixing the risk part",
	values:  []string{"0.3/edge,!stable"},
	err:     `"0.3/edge,!stable": '!' must prefix the whole risk`,
}, {
	summary: "Repeated risk",
	values:  []string{"0.3/edge,edge"},
	err:     `"0.3/edge,edge": risk "edge" is repeated`,
}, {
	summary: "Spaces",
	values:  []string{"0.3/not stable"},
	err:     `"0.3/not stable": must not contain spaces`,
}, {
	summary: "Repeated track",
	values:  []string{"0.3/*", "0.3/edge"},
	err:     `track "0.3" is repeated`,
}, {
	summary: "Repeated track with identical values",
	values:  []string{"0.3/edge", "0.3/edge"},
	err:     `track "0.3" is repeated`,
}}

func (s *S) TestChannelPatterns(c *C) {
	for _, test := range channelPatternTests {
		c.Logf("Summary: %s", test.summary)

		err := setup.ValidateChannelPatterns(test.values)
		if test.err != "" {
			c.Assert(err, ErrorMatches, test.err)
			continue
		}
		c.Assert(err, IsNil)

		for channel, expected := range test.match {
			c.Assert(setup.MatchChannelPatterns(test.values, channel), Equals, expected,
				Commentf("channel %q", channel.String()))
		}
	}
}
