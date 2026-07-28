package setup

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// The "channel" field of a slice definition holds patterns selecting which
// concrete "<track>/<risk>" channels an entry applies to. The track is a
// literal and only the risk part accepts operators:
//
//	*            - Any risk of that track
//	!<risk>      - Any risk of that track but that one
//	<risk>[,...] - Only those risks of that track
//
// Patterns are kept as written and interpreted on each match, as done for
// globs in the strdist package. They are validated when the release is read so
// that a malformed value is reported early, and rendered back verbatim.

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
		if err := validateRisk(segments[1]); err != nil {
			return Channel{}, fmt.Errorf("channel has %s", err)
		}
		parsed.Risk = segments[1]
	}
	if len(segments) > 2 {
		parsed.Branch = segments[2]
	}
	return parsed, nil
}

// knownRisks holds every risk a channel may hold, from the most to the least
// stable. The set is defined by the store and does not depend on its content,
// hence risks are validated as architectures are.
var knownRisks = []string{"stable", "candidate", "beta", "edge"}

// validateRisk validates a single risk of a channel or of a channel pattern.
func validateRisk(risk string) error {
	if !slices.Contains(knownRisks, risk) {
		return fmt.Errorf("unknown risk %q, must be one of %s", risk, strings.Join(knownRisks, ", "))
	}
	return nil
}

// validateChannelPatterns validates the values of a "channel" field. A track
// may appear at most once across the values so that the resulting set of
// channels is unambiguous.
func validateChannelPatterns(patterns []string) error {
	for i, pattern := range patterns {
		track, err := validateChannelPattern(pattern)
		if err != nil {
			return fmt.Errorf("%q: %s", pattern, err)
		}
		for _, seen := range patterns[:i] {
			// The pattern is only valid, hence the track is well defined.
			if seenTrack, _, _ := strings.Cut(seen, "/"); seenTrack == track {
				return fmt.Errorf("track %q is repeated", track)
			}
		}
	}
	return nil
}

// validateChannelPattern validates a single pattern and returns its track.
func validateChannelPattern(pattern string) (track string, err error) {
	if strings.ContainsFunc(pattern, unicode.IsSpace) {
		return "", errors.New("must not contain spaces")
	}
	track, riskPart, ok := strings.Cut(pattern, "/")
	if !ok || track == "" || riskPart == "" {
		return "", errors.New("must be <track>/<risk>")
	}
	if strings.ContainsAny(track, "*!,") {
		return "", errors.New("only the risk accepts '*', '!' and ','")
	}
	if riskPart == "*" {
		return track, nil
	}
	if strings.Contains(riskPart, "*") {
		return "", errors.New("'*' must be the whole risk")
	}
	risks := strings.Split(riskPart, ",")
	if except, ok := strings.CutPrefix(riskPart, "!"); ok {
		if len(risks) > 1 {
			return "", errors.New("'!' cannot be combined with other risks")
		}
		if except == "" {
			return "", errors.New("must be <track>/<risk>")
		}
		if err := validateRisk(except); err != nil {
			return "", err
		}
		return track, nil
	}
	for i, risk := range risks {
		if risk == "" {
			return "", errors.New("must be <track>/<risk>")
		}
		if strings.Contains(risk, "!") {
			return "", errors.New("'!' must prefix the whole risk")
		}
		if slices.Contains(risks[:i], risk) {
			return "", fmt.Errorf("risk %q is repeated", risk)
		}
		if err := validateRisk(risk); err != nil {
			return "", err
		}
	}
	return track, nil
}

// MatchChannelPatterns reports whether the concrete "<track>/<risk>" channel
// matches any of the patterns. An empty list matches every channel, which means
// the entry is not channel specific.
//
// A branch, as in "<track>/<risk>/<branch>", is ignored. Branches are ephemeral
// and thus never part of a pattern, so an entry applies to every branch of the
// risk it matches.
func MatchChannelPatterns(patterns []string, channel string) bool {
	if len(patterns) == 0 {
		return true
	}
	track, risk, _ := strings.Cut(channel, "/")
	risk, _, _ = strings.Cut(risk, "/")
	if track == "" || risk == "" {
		// A channel without a risk is not a channel. Never match it, rather
		// than treat the missing risk as one that differs from an excluded one.
		return false
	}
	for _, pattern := range patterns {
		if matchChannel(pattern, track, risk) {
			return true
		}
	}
	return false
}

// matchChannel reports whether the pattern matches the track and the risk of a
// concrete channel. Note that the exclusion form is scoped to its own track, so
// "1.0/!stable" does not match any risk of the "2.0" track.
//
// The pattern is expected to be valid, as ensured when the release is read.
func matchChannel(pattern, track, risk string) bool {
	patternTrack, riskPart, _ := strings.Cut(pattern, "/")
	if track != patternTrack {
		return false
	}
	if riskPart == "*" {
		return true
	}
	if except, ok := strings.CutPrefix(riskPart, "!"); ok {
		return risk != except
	}
	return slices.Contains(strings.Split(riskPart, ","), risk)
}
