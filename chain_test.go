package main

import "testing"
import "github.com/stretchr/testify/assert"

var (
	iptablesOutput = `Chain INPUT (policy DROP)
target     prot opt source               destination         
fail2ban-ssh  tcp  --  0.0.0.0/0            0.0.0.0/0            multiport dports 22
fail2ban-ssh  tcp  --  0.0.0.0/0            0.0.0.0/0            multiport dports 22
fail2ban-ssh  tcp  --  0.0.0.0/0            0.0.0.0/0            multiport dports 22
ACCEPT     all  --  127.0.0.1            0.0.0.0/0           
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
ACCEPT     all  --  192.168.1.0/24       0.0.0.0/0           
ACCEPT     all  --  192.168.2.0/24       0.0.0.0/0           
ACCEPT     all  --  192.168.3.0/24       0.0.0.0/0           
ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0            icmptype 8
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:1234 /* Open 1234 port */
ACCEPT     udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:123 /* NTP */
LOG        all  --  0.0.0.0/0            0.0.0.0/0            limit: avg 1/min burst 5 LOG flags 0 level 4 prefix "iptables-INPUT-DROP: "
`
)

func TestReadingIPTablesOutput(t *testing.T) {
	ci, err := newChainInfo(iptablesOutput)
	assert.Nil(t, err)
	assert.NotNil(t, ci)
	assert.Equal(t, "INPUT", ci.ChainName)
	assert.Equal(t, "DROP", ci.PolicyName)
	assert.Equal(t, 1, ci.CountRules("LOG"))
	assert.Equal(t, 3, ci.CountRules("fail2ban-ssh"))
	assert.Equal(t, 8, ci.CountRules("ACCEPT"))
	assert.Equal(t, 2, ci.CommentedRules())
}
