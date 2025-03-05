# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_edamame_posture_global_optspecs
	string join \n v/verbose h/help V/version
end

function __fish_edamame_posture_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_edamame_posture_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_edamame_posture_using_subcommand
	set -l cmd (__fish_edamame_posture_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -s V -l version -d 'Print version'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "completion" -d 'Generate shell completion scripts'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "get-score" -d 'Get score information'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "lanscan" -d 'Performs a LAN scan'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "capture" -d 'Capture packets'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "get-core-info" -d 'Get core information'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "get-device-info" -d 'Get device information'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "get-system-info" -d 'Get system information'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "request-pin" -d 'Request PIN'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "get-core-version" -d 'Get core version'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "remediate-all-threats" -d 'Remediate all threats but excluding remote login enabled and local firewall disabled as well as other threats specified in the comma separated list'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "remediate-all-threats-force" -d 'Remediate all threats, including threats that could lock you out of the system, use with caution!'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "remediate-threat" -d 'Remediate a threat'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "rollback-threat" -d 'Rollback a threat'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "list-threats" -d 'List all threat names'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "get-threat-info" -d 'Get threat information'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "request-signature" -d 'Report the security posture anonymously and get a signature for later retrieval'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "request-report" -d 'Send a report from a signature to an email address'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "check-policy-for-domain" -d 'Check a policy against a specific domain in the hub'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "check-policy" -d 'Check locally if the current system meets the specified policy requirements'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "get-tag-prefixes" -d 'Get threat model tag prefixes'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "background-logs" -d 'Display logs from the background process'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "background-wait-for-connection" -d 'Wait for connection of the background process'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "background-sessions" -d 'Get connections of the background process'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "background-threats-info" -d 'Get threats information of the background process'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "foreground-start" -d 'Start reporting in the foreground (used by the systemd service)'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "background-start" -d 'Start reporting background process'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "background-stop" -d 'Stop reporting background process'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "background-status" -d 'Get status of reporting background process'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "background-last-report-signature" -d 'Get last report signature of background process'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "background-get-history" -d 'Get history of score modifications'
complete -c edamame_posture -n "__fish_edamame_posture_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand completion" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand completion" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-score" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-score" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand lanscan" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand lanscan" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand capture" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand capture" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-core-info" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-core-info" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-device-info" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-device-info" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-system-info" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-system-info" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand request-pin" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand request-pin" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-core-version" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-core-version" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand remediate-all-threats" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand remediate-all-threats" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand remediate-all-threats-force" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand remediate-all-threats-force" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand remediate-threat" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand remediate-threat" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand rollback-threat" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand rollback-threat" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand list-threats" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand list-threats" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-threat-info" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-threat-info" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand request-signature" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand request-signature" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand request-report" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand request-report" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand check-policy-for-domain" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand check-policy-for-domain" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand check-policy" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand check-policy" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-tag-prefixes" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand get-tag-prefixes" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-logs" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-logs" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-wait-for-connection" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-wait-for-connection" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-sessions" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-sessions" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-threats-info" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-threats-info" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand foreground-start" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand foreground-start" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-start" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-start" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-stop" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-stop" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-status" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-status" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-last-report-signature" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-last-report-signature" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-get-history" -s v -l verbose -d 'Verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand background-get-history" -s h -l help -d 'Print help'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "completion" -d 'Generate shell completion scripts'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "get-score" -d 'Get score information'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "lanscan" -d 'Performs a LAN scan'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "capture" -d 'Capture packets'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "get-core-info" -d 'Get core information'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "get-device-info" -d 'Get device information'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "get-system-info" -d 'Get system information'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "request-pin" -d 'Request PIN'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "get-core-version" -d 'Get core version'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "remediate-all-threats" -d 'Remediate all threats but excluding remote login enabled and local firewall disabled as well as other threats specified in the comma separated list'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "remediate-all-threats-force" -d 'Remediate all threats, including threats that could lock you out of the system, use with caution!'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "remediate-threat" -d 'Remediate a threat'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "rollback-threat" -d 'Rollback a threat'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "list-threats" -d 'List all threat names'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "get-threat-info" -d 'Get threat information'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "request-signature" -d 'Report the security posture anonymously and get a signature for later retrieval'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "request-report" -d 'Send a report from a signature to an email address'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "check-policy-for-domain" -d 'Check a policy against a specific domain in the hub'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "check-policy" -d 'Check locally if the current system meets the specified policy requirements'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "get-tag-prefixes" -d 'Get threat model tag prefixes'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "background-logs" -d 'Display logs from the background process'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "background-wait-for-connection" -d 'Wait for connection of the background process'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "background-sessions" -d 'Get connections of the background process'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "background-threats-info" -d 'Get threats information of the background process'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "foreground-start" -d 'Start reporting in the foreground (used by the systemd service)'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "background-start" -d 'Start reporting background process'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "background-stop" -d 'Stop reporting background process'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "background-status" -d 'Get status of reporting background process'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "background-last-report-signature" -d 'Get last report signature of background process'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "background-get-history" -d 'Get history of score modifications'
complete -c edamame_posture -n "__fish_edamame_posture_using_subcommand help; and not __fish_seen_subcommand_from completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy get-tag-prefixes background-logs background-wait-for-connection background-sessions background-threats-info foreground-start background-start background-stop background-status background-last-report-signature background-get-history help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
