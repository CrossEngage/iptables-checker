# iptables-checker

Simple tool to count iptables rules and print InfluxDB compatible output.

This tool is meant to be used with Telegraf's `inputs.exec` plugin.

The tool needs to have setuid to be able to run `iptables` or `ip6tables`.