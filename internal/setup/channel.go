package setup

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// Channel is a store channel, as in "<track>/<risk>[/<branch>]".
type Channel struct {
	Track  string
	Risk   string
	Branch string
}

func (c Channel) String() string {
	if c.Track == "" {
		return ""
	}
	channel := c.Track
	if c.Risk != "" {
		channel += "/" + c.Risk
	}
	if c.Branch != "" {
		channel += "/" + c.Branch
	}
	return channel
}

// parseChannel parses a "<track>[/<risk>[/<branch>]]" channel, as written.
// Validation is intentionally loose, the track, the risk and the branch are
// only checked for their presence so that their values are not rejected here.
func parseChannel(channel string) (Channel, error) {
	if channel == "" {
		return Channel{}, errors.New("missing channel")
	}
	if strings.ContainsFunc(channel, unicode.IsSpace) {
		return Channel{}, errors.New("channel must not contain spaces")
	}
	segments := strings.Split(channel, "/")
	if len(segments) > 3 {
		return Channel{}, errors.New("channel must be <track>[/<risk>[/<branch>]]")
	}
	for _, segment := range segments {
		if segment == "" {
			return Channel{}, errors.New("channel must be <track>[/<risk>[/<branch>]]")
		}
	}
	parsed := Channel{Track: segments[0]}
	if len(segments) > 1 {
		parsed.Risk = segments[1]
	}
	if len(segments) > 2 {
		parsed.Branch = segments[2]
	}
	return parsed, nil
}

// channelShape tells how the risk part of a [ChannelFilter] must be
// interpreted.
type channelShape int

const (
	// allRisks is the "<track>/*" form.
	allRisks channelShape = iota
	// exceptRisk is the "<track>/!<risk>" form.
	exceptRisk
	// theseRisks is the "<track>/<risk>[,<risk>]" form.
	theseRisks
)

// ChannelFilter selects which concrete channels of a single track some slice
// definition entry applies to. It is a pattern, as opposed to the concrete
// "<track>/<risk>" channels held by [Selection.Channels].
type ChannelFilter struct {
	// Track is the literal track name. Wildcards are not allowed here.
	Track string
	// Risks holds the risks the filter is about. It is empty for the "*" form
	// and holds a single entry for the "!<risk>" form.
	Risks []string
	shape channelShape
}

// String returns the canonical representation of the filter. It is lossless,
// that is, parsing it back yields an equal filter.
func (f ChannelFilter) String() string {
	switch f.shape {
	case allRisks:
		return f.Track + "/*"
	case exceptRisk:
		return f.Track + "/!" + f.Risks[0]
	}
	return f.Track + "/" + strings.Join(f.Risks, ",")
}

// Match reports whether the filter matches the concrete "<track>/<risk>"
// channel. Note that the exclusion form is scoped to its own track, so
// "1.0/!stable" does not match any risk of the "2.0" track.
func (f ChannelFilter) Match(channel string) bool {
	track, risk, _ := strings.Cut(channel, "/")
	if track != f.Track {
		return false
	}
	switch f.shape {
	case allRisks:
		return true
	case exceptRisk:
		return risk != f.Risks[0]
	}
	return slices.Contains(f.Risks, risk)
}

// MatchChannelFilters reports whether the concrete "<track>/<risk>" channel
// matches any of the filters. An empty list matches every channel, which means
// the entry is not channel specific.
func MatchChannelFilters(filters []ChannelFilter, channel string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, filter := range filters {
		if filter.Match(channel) {
			return true
		}
	}
	return false
}

// ParseChannelFilters parses and validates the values of a "channel" field.
// Each value is a "<track>/<risk>" pattern where only the risk part accepts
// the "*", "!" and "," operators. A track may appear at most once across the
// values so that the resulting set of channels is unambiguous.
func ParseChannelFilters(values []string) ([]ChannelFilter, error) {
	if len(values) == 0 {
		return nil, nil
	}
	filters := make([]ChannelFilter, 0, len(values))
	for _, value := range values {
		filter, err := parseChannelFilter(value)
		if err != nil {
			return nil, fmt.Errorf("%q: %s", value, err)
		}
		for _, seen := range filters {
			if seen.Track == filter.Track {
				return nil, fmt.Errorf("track %q is repeated", filter.Track)
			}
		}
		filters = append(filters, filter)
	}
	return filters, nil
}

func parseChannelFilter(value string) (ChannelFilter, error) {
	if strings.ContainsFunc(value, unicode.IsSpace) {
		return ChannelFilter{}, fmt.Errorf("must not contain spaces")
	}
	track, riskPart, ok := strings.Cut(value, "/")
	if !ok || track == "" || riskPart == "" {
		return ChannelFilter{}, fmt.Errorf("must be <track>/<risk>")
	}
	if strings.ContainsAny(track, "*!,") {
		return ChannelFilter{}, fmt.Errorf("only the risk accepts '*', '!' and ','")
	}
	if riskPart == "*" {
		return ChannelFilter{Track: track, shape: allRisks}, nil
	}
	if strings.Contains(riskPart, "*") {
		return ChannelFilter{}, fmt.Errorf("'*' must be the whole risk")
	}
	risks := strings.Split(riskPart, ",")
	if except, ok := strings.CutPrefix(riskPart, "!"); ok {
		if len(risks) > 1 {
			return ChannelFilter{}, fmt.Errorf("'!' cannot be combined with other risks")
		}
		if except == "" {
			return ChannelFilter{}, fmt.Errorf("must be <track>/<risk>")
		}
		return ChannelFilter{Track: track, Risks: []string{except}, shape: exceptRisk}, nil
	}
	for i, risk := range risks {
		if risk == "" {
			return ChannelFilter{}, fmt.Errorf("must be <track>/<risk>")
		}
		if strings.Contains(risk, "!") {
			return ChannelFilter{}, fmt.Errorf("'!' must prefix the whole risk")
		}
		if slices.Contains(risks[:i], risk) {
			return ChannelFilter{}, fmt.Errorf("risk %q is repeated", risk)
		}
	}
	return ChannelFilter{Track: track, Risks: risks, shape: theseRisks}, nil
}
