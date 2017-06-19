//go:generate bash ./g_version.sh
package main

import (
	"bytes"
	"fmt"
	"log/syslog"
	"os"
	"path"

	"os/exec"

	"log"

	"gopkg.in/alecthomas/kingpin.v1"
)

var (
	appName    = path.Base(os.Args[0])
	app        = kingpin.New(appName, "A command-line checker for IPtables rules, by CrossEngage")
	ipVersions = app.Flag("ipvs", "which IP versions to check").Default("v4").Enums("v4", "v6")
	checkName  = app.Flag("name", "check name").Default(appName).String()
	chains     = app.Arg("chains", "iptables chains to monitor").Required().Strings()
	ipVBin     = map[string]string{"v4": "iptables", "v6": "ip6tables"}
)

func main() {
	app.Version(version)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	slog, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_DAEMON, appName)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(slog)

	for _, chain := range *chains {
		for _, ipv := range *ipVersions {
			bin := ipVBin[ipv]
			cmd := exec.Command(bin, "-nL", chain)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			if err != nil {
				log.Fatalf("Failed running `%s` with error `%s`\n", bin, err)
			}

			outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
			slog.Debug(fmt.Sprintf("%s: stdout `%s`, stderr `%s`", bin, outStr, errStr))

			c, err := newChainInfo(outStr)
			if err != nil {
				slog.Err(fmt.Sprintf("Could not parse `%s` stdout: `%s`", bin, outStr))
			}

			fmt.Printf(
				`%s,chain_name=%s,chain_ipv=%s chain_policy="%s",total_rules=%d,rules_with_comments=%d,rules_with_logs=%d`,
				*checkName, c.ChainName, ipv, c.PolicyName, len(c.Rules), c.CommentedRules(), c.CountRules("LOG"),
			)
			fmt.Println()
		}
	}
}
