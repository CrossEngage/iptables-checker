package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

var (
	policyRgx  = regexp.MustCompile(`Chain (\w+) \(policy (\w+)\)`)
	columnRgx  = regexp.MustCompile(`\s+`)
	commentRgx = regexp.MustCompile(`\/\*.+\*\/`)

	errCouldNotParseCmdOut = "Unknown command output: %s"
)

type chainInfo struct {
	ChainName  string
	PolicyName string
	Rules      []rule
}

func (ci chainInfo) CommentedRules() int {
	count := 0
	for _, rule := range ci.Rules {
		if rule.HasComment() {
			count++
		}
	}
	return count
}

func (ci chainInfo) CountRules(target string) int {
	count := 0
	for _, rule := range ci.Rules {
		if rule.Target == target {
			count++
		}
	}
	return count
}

func newChainInfo(stdout string) (*chainInfo, error) {
	lines := strings.Split(stdout, "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf(errCouldNotParseCmdOut, stdout)
	}

	matches := policyRgx.FindAllStringSubmatch(stdout, -1)
	if len(matches) != 1 {
		return nil, fmt.Errorf(errCouldNotParseCmdOut, stdout)
	}

	info := &chainInfo{}
	info.ChainName = matches[0][1]
	info.PolicyName = matches[0][2]
	info.Rules = make([]rule, 0)

	for _, line := range lines[2:] {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		r, err := newRuleFromLine(line)
		if err != nil {
			log.Println(err)
		}
		info.Rules = append(info.Rules, *r)
	}

	return info, nil
}
