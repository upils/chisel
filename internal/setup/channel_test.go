package setup_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/setup"
)

var channelFilterTests = []struct {
	summary string
	values  []string
	err     string
	// canonical is the rendering of the parsed filters. It defaults to values.
	canonical []string
	// match maps a concrete channel to whether the filters match it.
	match map[string]bool
}{{
	summary: "No filter matches every channel",
	values:  nil,
	match:   map[string]bool{"3.0/stable": true, "2.0/edge": true},
}, {
	summary: "Precise channel",
	values:  []string{"0.3/stable"},
	match: map[string]bool{
		"0.3/stable": true,
		"0.3/edge":   false,
		"0.2/stable": false,
	},
}, {
	summary: "All risks of a track",
	values:  []string{"0.3/*"},
	match: map[string]bool{
		"0.3/stable": true,
		"0.3/edge":   true,
		"0.2/stable": false,
	},
}, {
	summary: "Excluded risk",
	values:  []string{"0.2/!stable"},
	match: map[string]bool{
		"0.2/stable": false,
		"0.2/edge":   true,
		"0.2/beta":   true,
		// The exclusion is scoped to its own track, it never means "any
		// other track".
		"0.3/edge": false,
	},
}, {
	summary: "Several risks",
	values:  []string{"0.2/beta,edge"},
	match: map[string]bool{
		"0.2/beta":   true,
		"0.2/edge":   true,
		"0.2/stable": false,
	},
}, {
	summary: "Union of several tracks",
	values:  []string{"0.2/!stable", "0.3/*"},
	match: map[string]bool{
		"0.2/edge":   true,
		"0.2/stable": false,
		"0.3/stable": true,
	},
}, {
	summary: "Risks are free-form",
	values:  []string{"0.3/whatever"},
	match:   map[string]bool{"0.3/whatever": true},
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

func (s *S) TestChannelFilters(c *C) {
	for _, test := range channelFilterTests {
		c.Logf("Summary: %s", test.summary)

		filters, err := setup.ParseChannelFilters(test.values)
		if test.err != "" {
			c.Assert(err, ErrorMatches, test.err)
			continue
		}
		c.Assert(err, IsNil)

		canonical := test.canonical
		if canonical == nil {
			canonical = test.values
		}
		rendered := []string(nil)
		for _, filter := range filters {
			rendered = append(rendered, filter.String())
		}
		c.Assert(rendered, DeepEquals, canonical)

		for channel, expected := range test.match {
			c.Assert(setup.MatchChannelFilters(filters, channel), Equals, expected,
				Commentf("channel %q", channel))
		}
	}
}
