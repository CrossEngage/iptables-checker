package main

import (
	"fmt"
)

type rule struct {
	Target      string
	Protocol    string
	Options     string
	Source      string
	Destination string
	Spec        string
}

func (r rule) HasComment() bool {
	return commentRgx.MatchString(r.Spec)
}

func newRuleFromLine(line string) (*rule, error) {
	cols := columnRgx.Split(line, 6)
	if len(cols) < 5 {
		return nil, fmt.Errorf("Could not read rule from `%s`", line)
	}
	r := &rule{
		Target:      cols[0],
		Protocol:    cols[1],
		Options:     cols[2],
		Source:      cols[3],
		Destination: cols[4],
	}
	if len(cols) >= 6 {
		r.Spec = cols[5]
	}
	return r, nil
}
