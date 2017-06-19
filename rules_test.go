package main

import "testing"
import "github.com/stretchr/testify/assert"

func TestRuleFromStringWith6Columns(t *testing.T) {
	r, err := newRuleFromLine(`ACCEPT     tcp  --  10.0.0.0/8            0.0.0.0/0            tcp dpt:1234 /* Open 1234 port */`)
	assert.NotNil(t, r)
	assert.Nil(t, err)
	assert.Equal(t, "ACCEPT", r.Target)
	assert.Equal(t, "tcp", r.Protocol)
	assert.Equal(t, "--", r.Options)
	assert.Equal(t, "10.0.0.0/8", r.Source)
	assert.Equal(t, "0.0.0.0/0", r.Destination)
	assert.Equal(t, "tcp dpt:1234 /* Open 1234 port */", r.Spec)
	assert.True(t, r.HasComment())
}

func TestRuleFromStringWith5Columns(t *testing.T) {
	r, err := newRuleFromLine(`ACCEPT     tcp  --  10.0.0.0/8            0.0.0.0/0`)
	assert.NotNil(t, r)
	assert.Nil(t, err)
	assert.Equal(t, "ACCEPT", r.Target)
	assert.Equal(t, "tcp", r.Protocol)
	assert.Equal(t, "--", r.Options)
	assert.Equal(t, "10.0.0.0/8", r.Source)
	assert.Equal(t, "0.0.0.0/0", r.Destination)
	assert.False(t, r.HasComment())
}

func TestRuleWithoutComment(t *testing.T) {
	r := rule{Spec: "tcp dpt:1234"}
	assert.False(t, r.HasComment())
}
