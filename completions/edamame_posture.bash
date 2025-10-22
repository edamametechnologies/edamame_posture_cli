_edamame_posture() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="edamame_posture"
                ;;
            edamame_posture,augment-custom-whitelists)
                cmd="edamame_posture__augment__custom__whitelists"
                ;;
            edamame_posture,background-create-and-set-custom-whitelists)
                cmd="edamame_posture__background__create__and__set__custom__whitelists"
                ;;
            edamame_posture,background-create-custom-whitelists)
                cmd="edamame_posture__background__create__custom__whitelists"
                ;;
            edamame_posture,background-get-anomalous-sessions)
                cmd="edamame_posture__background__get__anomalous__sessions"
                ;;
            edamame_posture,background-get-blacklisted-sessions)
                cmd="edamame_posture__background__get__blacklisted__sessions"
                ;;
            edamame_posture,background-get-blacklists)
                cmd="edamame_posture__background__get__blacklists"
                ;;
            edamame_posture,background-get-exceptions)
                cmd="edamame_posture__background__get__exceptions"
                ;;
            edamame_posture,background-get-history)
                cmd="edamame_posture__background__get__history"
                ;;
            edamame_posture,background-get-sessions)
                cmd="edamame_posture__background__get__sessions"
                ;;
            edamame_posture,background-get-whitelist-name)
                cmd="edamame_posture__background__get__whitelist__name"
                ;;
            edamame_posture,background-get-whitelists)
                cmd="edamame_posture__background__get__whitelists"
                ;;
            edamame_posture,background-last-report-signature)
                cmd="edamame_posture__background__last__report__signature"
                ;;
            edamame_posture,background-logs)
                cmd="edamame_posture__background__logs"
                ;;
            edamame_posture,background-mcp-generate-psk)
                cmd="edamame_posture__background__mcp__generate__psk"
                ;;
            edamame_posture,background-mcp-start)
                cmd="edamame_posture__background__mcp__start"
                ;;
            edamame_posture,background-mcp-status)
                cmd="edamame_posture__background__mcp__status"
                ;;
            edamame_posture,background-mcp-stop)
                cmd="edamame_posture__background__mcp__stop"
                ;;
            edamame_posture,background-score)
                cmd="edamame_posture__background__score"
                ;;
            edamame_posture,background-set-custom-blacklists)
                cmd="edamame_posture__background__set__custom__blacklists"
                ;;
            edamame_posture,background-set-custom-blacklists-from-file)
                cmd="edamame_posture__background__set__custom__blacklists__from__file"
                ;;
            edamame_posture,background-set-custom-whitelists)
                cmd="edamame_posture__background__set__custom__whitelists"
                ;;
            edamame_posture,background-set-custom-whitelists-from-file)
                cmd="edamame_posture__background__set__custom__whitelists__from__file"
                ;;
            edamame_posture,background-start)
                cmd="edamame_posture__background__start"
                ;;
            edamame_posture,background-start-disconnected)
                cmd="edamame_posture__background__start__disconnected"
                ;;
            edamame_posture,background-status)
                cmd="edamame_posture__background__status"
                ;;
            edamame_posture,background-stop)
                cmd="edamame_posture__background__stop"
                ;;
            edamame_posture,background-threats-info)
                cmd="edamame_posture__background__threats__info"
                ;;
            edamame_posture,background-wait-for-connection)
                cmd="edamame_posture__background__wait__for__connection"
                ;;
            edamame_posture,capture)
                cmd="edamame_posture__capture"
                ;;
            edamame_posture,check-policy)
                cmd="edamame_posture__check__policy"
                ;;
            edamame_posture,check-policy-for-domain)
                cmd="edamame_posture__check__policy__for__domain"
                ;;
            edamame_posture,check-policy-for-domain-with-signature)
                cmd="edamame_posture__check__policy__for__domain__with__signature"
                ;;
            edamame_posture,completion)
                cmd="edamame_posture__completion"
                ;;
            edamame_posture,foreground-start)
                cmd="edamame_posture__foreground__start"
                ;;
            edamame_posture,get-core-info)
                cmd="edamame_posture__get__core__info"
                ;;
            edamame_posture,get-core-version)
                cmd="edamame_posture__get__core__version"
                ;;
            edamame_posture,get-device-info)
                cmd="edamame_posture__get__device__info"
                ;;
            edamame_posture,get-score)
                cmd="edamame_posture__get__score"
                ;;
            edamame_posture,get-system-info)
                cmd="edamame_posture__get__system__info"
                ;;
            edamame_posture,get-tag-prefixes)
                cmd="edamame_posture__get__tag__prefixes"
                ;;
            edamame_posture,get-threat-info)
                cmd="edamame_posture__get__threat__info"
                ;;
            edamame_posture,help)
                cmd="edamame_posture__help"
                ;;
            edamame_posture,lanscan)
                cmd="edamame_posture__lanscan"
                ;;
            edamame_posture,list-threats)
                cmd="edamame_posture__list__threats"
                ;;
            edamame_posture,merge-custom-whitelists)
                cmd="edamame_posture__merge__custom__whitelists"
                ;;
            edamame_posture,merge-custom-whitelists-from-files)
                cmd="edamame_posture__merge__custom__whitelists__from__files"
                ;;
            edamame_posture,remediate-all-threats)
                cmd="edamame_posture__remediate__all__threats"
                ;;
            edamame_posture,remediate-all-threats-force)
                cmd="edamame_posture__remediate__all__threats__force"
                ;;
            edamame_posture,remediate-threat)
                cmd="edamame_posture__remediate__threat"
                ;;
            edamame_posture,request-pin)
                cmd="edamame_posture__request__pin"
                ;;
            edamame_posture,request-report)
                cmd="edamame_posture__request__report"
                ;;
            edamame_posture,request-signature)
                cmd="edamame_posture__request__signature"
                ;;
            edamame_posture,rollback-threat)
                cmd="edamame_posture__rollback__threat"
                ;;
            edamame_posture__help,augment-custom-whitelists)
                cmd="edamame_posture__help__augment__custom__whitelists"
                ;;
            edamame_posture__help,background-create-and-set-custom-whitelists)
                cmd="edamame_posture__help__background__create__and__set__custom__whitelists"
                ;;
            edamame_posture__help,background-create-custom-whitelists)
                cmd="edamame_posture__help__background__create__custom__whitelists"
                ;;
            edamame_posture__help,background-get-anomalous-sessions)
                cmd="edamame_posture__help__background__get__anomalous__sessions"
                ;;
            edamame_posture__help,background-get-blacklisted-sessions)
                cmd="edamame_posture__help__background__get__blacklisted__sessions"
                ;;
            edamame_posture__help,background-get-blacklists)
                cmd="edamame_posture__help__background__get__blacklists"
                ;;
            edamame_posture__help,background-get-exceptions)
                cmd="edamame_posture__help__background__get__exceptions"
                ;;
            edamame_posture__help,background-get-history)
                cmd="edamame_posture__help__background__get__history"
                ;;
            edamame_posture__help,background-get-sessions)
                cmd="edamame_posture__help__background__get__sessions"
                ;;
            edamame_posture__help,background-get-whitelist-name)
                cmd="edamame_posture__help__background__get__whitelist__name"
                ;;
            edamame_posture__help,background-get-whitelists)
                cmd="edamame_posture__help__background__get__whitelists"
                ;;
            edamame_posture__help,background-last-report-signature)
                cmd="edamame_posture__help__background__last__report__signature"
                ;;
            edamame_posture__help,background-logs)
                cmd="edamame_posture__help__background__logs"
                ;;
            edamame_posture__help,background-mcp-generate-psk)
                cmd="edamame_posture__help__background__mcp__generate__psk"
                ;;
            edamame_posture__help,background-mcp-start)
                cmd="edamame_posture__help__background__mcp__start"
                ;;
            edamame_posture__help,background-mcp-status)
                cmd="edamame_posture__help__background__mcp__status"
                ;;
            edamame_posture__help,background-mcp-stop)
                cmd="edamame_posture__help__background__mcp__stop"
                ;;
            edamame_posture__help,background-score)
                cmd="edamame_posture__help__background__score"
                ;;
            edamame_posture__help,background-set-custom-blacklists)
                cmd="edamame_posture__help__background__set__custom__blacklists"
                ;;
            edamame_posture__help,background-set-custom-blacklists-from-file)
                cmd="edamame_posture__help__background__set__custom__blacklists__from__file"
                ;;
            edamame_posture__help,background-set-custom-whitelists)
                cmd="edamame_posture__help__background__set__custom__whitelists"
                ;;
            edamame_posture__help,background-set-custom-whitelists-from-file)
                cmd="edamame_posture__help__background__set__custom__whitelists__from__file"
                ;;
            edamame_posture__help,background-start)
                cmd="edamame_posture__help__background__start"
                ;;
            edamame_posture__help,background-start-disconnected)
                cmd="edamame_posture__help__background__start__disconnected"
                ;;
            edamame_posture__help,background-status)
                cmd="edamame_posture__help__background__status"
                ;;
            edamame_posture__help,background-stop)
                cmd="edamame_posture__help__background__stop"
                ;;
            edamame_posture__help,background-threats-info)
                cmd="edamame_posture__help__background__threats__info"
                ;;
            edamame_posture__help,background-wait-for-connection)
                cmd="edamame_posture__help__background__wait__for__connection"
                ;;
            edamame_posture__help,capture)
                cmd="edamame_posture__help__capture"
                ;;
            edamame_posture__help,check-policy)
                cmd="edamame_posture__help__check__policy"
                ;;
            edamame_posture__help,check-policy-for-domain)
                cmd="edamame_posture__help__check__policy__for__domain"
                ;;
            edamame_posture__help,check-policy-for-domain-with-signature)
                cmd="edamame_posture__help__check__policy__for__domain__with__signature"
                ;;
            edamame_posture__help,completion)
                cmd="edamame_posture__help__completion"
                ;;
            edamame_posture__help,foreground-start)
                cmd="edamame_posture__help__foreground__start"
                ;;
            edamame_posture__help,get-core-info)
                cmd="edamame_posture__help__get__core__info"
                ;;
            edamame_posture__help,get-core-version)
                cmd="edamame_posture__help__get__core__version"
                ;;
            edamame_posture__help,get-device-info)
                cmd="edamame_posture__help__get__device__info"
                ;;
            edamame_posture__help,get-score)
                cmd="edamame_posture__help__get__score"
                ;;
            edamame_posture__help,get-system-info)
                cmd="edamame_posture__help__get__system__info"
                ;;
            edamame_posture__help,get-tag-prefixes)
                cmd="edamame_posture__help__get__tag__prefixes"
                ;;
            edamame_posture__help,get-threat-info)
                cmd="edamame_posture__help__get__threat__info"
                ;;
            edamame_posture__help,help)
                cmd="edamame_posture__help__help"
                ;;
            edamame_posture__help,lanscan)
                cmd="edamame_posture__help__lanscan"
                ;;
            edamame_posture__help,list-threats)
                cmd="edamame_posture__help__list__threats"
                ;;
            edamame_posture__help,merge-custom-whitelists)
                cmd="edamame_posture__help__merge__custom__whitelists"
                ;;
            edamame_posture__help,merge-custom-whitelists-from-files)
                cmd="edamame_posture__help__merge__custom__whitelists__from__files"
                ;;
            edamame_posture__help,remediate-all-threats)
                cmd="edamame_posture__help__remediate__all__threats"
                ;;
            edamame_posture__help,remediate-all-threats-force)
                cmd="edamame_posture__help__remediate__all__threats__force"
                ;;
            edamame_posture__help,remediate-threat)
                cmd="edamame_posture__help__remediate__threat"
                ;;
            edamame_posture__help,request-pin)
                cmd="edamame_posture__help__request__pin"
                ;;
            edamame_posture__help,request-report)
                cmd="edamame_posture__help__request__report"
                ;;
            edamame_posture__help,request-signature)
                cmd="edamame_posture__help__request__signature"
                ;;
            edamame_posture__help,rollback-threat)
                cmd="edamame_posture__help__rollback__threat"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        edamame_posture)
            opts="-v -h -V --verbose --help --version completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy-for-domain-with-signature check-policy get-tag-prefixes background-logs background-wait-for-connection background-get-sessions background-get-exceptions background-threats-info foreground-start background-start background-stop background-mcp-start background-mcp-stop background-mcp-status background-mcp-generate-psk background-status background-last-report-signature background-get-history background-start-disconnected background-set-custom-whitelists background-set-custom-whitelists-from-file background-create-custom-whitelists background-create-and-set-custom-whitelists background-set-custom-blacklists background-set-custom-blacklists-from-file background-score background-get-anomalous-sessions background-get-blacklisted-sessions background-get-blacklists background-get-whitelists background-get-whitelist-name augment-custom-whitelists merge-custom-whitelists merge-custom-whitelists-from-files help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__augment__custom__whitelists)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__create__and__set__custom__whitelists)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__create__custom__whitelists)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__get__anomalous__sessions)
            opts="-v -h --verbose --help true false"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__get__blacklisted__sessions)
            opts="-v -h --verbose --help true false"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__get__blacklists)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__get__exceptions)
            opts="-v -h --verbose --help true false true false"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__get__history)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__get__sessions)
            opts="-v -h --verbose --help true false true false true false true false true false"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__get__whitelist__name)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__get__whitelists)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__last__report__signature)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__logs)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__mcp__generate__psk)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__mcp__start)
            opts="-v -h --verbose --help [PORT] [PSK]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__mcp__status)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__mcp__stop)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__score)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__set__custom__blacklists)
            opts="-v -h --verbose --help <BLACKLIST_JSON>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__set__custom__blacklists__from__file)
            opts="-v -h --verbose --help <BLACKLIST_FILE>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__set__custom__whitelists)
            opts="-v -h --verbose --help <WHITELIST_JSON>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__set__custom__whitelists__from__file)
            opts="-v -h --verbose --help <WHITELIST_FILE>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__start)
            opts="-v -h --verbose --help <USER> <DOMAIN> <PIN> [DEVICE_ID] true false [WHITELIST_NAME] true false auto semi manual disabled claude openai ollama none [AGENTIC_INTERVAL]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__start__disconnected)
            opts="-v -h --verbose --help true false [WHITELIST_NAME] true false"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__status)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__stop)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__threats__info)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__background__wait__for__connection)
            opts="-v -h --verbose --help [TIMEOUT]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__capture)
            opts="-v -h --verbose --help [SECONDS] [WHITELIST_NAME] true false true false"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__check__policy)
            opts="-v -h --verbose --help <MINIMUM_SCORE> <THREAT_IDS> [TAG_PREFIXES]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__check__policy__for__domain)
            opts="-v -h --verbose --help <DOMAIN> <POLICY_NAME>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__check__policy__for__domain__with__signature)
            opts="-v -h --verbose --help <SIGNATURE> <DOMAIN> <POLICY_NAME>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__completion)
            opts="-v -h --verbose --help bash elvish fish powershell zsh"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__foreground__start)
            opts="-v -h --verbose --help <USER> <DOMAIN> <PIN> auto semi manual disabled claude openai ollama none [AGENTIC_INTERVAL]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__get__core__info)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__get__core__version)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__get__device__info)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__get__score)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__get__system__info)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__get__tag__prefixes)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__get__threat__info)
            opts="-v -h --verbose --help <THREAT_ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help)
            opts="completion get-score lanscan capture get-core-info get-device-info get-system-info request-pin get-core-version remediate-all-threats remediate-all-threats-force remediate-threat rollback-threat list-threats get-threat-info request-signature request-report check-policy-for-domain check-policy-for-domain-with-signature check-policy get-tag-prefixes background-logs background-wait-for-connection background-get-sessions background-get-exceptions background-threats-info foreground-start background-start background-stop background-mcp-start background-mcp-stop background-mcp-status background-mcp-generate-psk background-status background-last-report-signature background-get-history background-start-disconnected background-set-custom-whitelists background-set-custom-whitelists-from-file background-create-custom-whitelists background-create-and-set-custom-whitelists background-set-custom-blacklists background-set-custom-blacklists-from-file background-score background-get-anomalous-sessions background-get-blacklisted-sessions background-get-blacklists background-get-whitelists background-get-whitelist-name augment-custom-whitelists merge-custom-whitelists merge-custom-whitelists-from-files help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__augment__custom__whitelists)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__create__and__set__custom__whitelists)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__create__custom__whitelists)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__get__anomalous__sessions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__get__blacklisted__sessions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__get__blacklists)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__get__exceptions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__get__history)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__get__sessions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__get__whitelist__name)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__get__whitelists)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__last__report__signature)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__logs)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__mcp__generate__psk)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__mcp__start)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__mcp__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__mcp__stop)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__score)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__set__custom__blacklists)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__set__custom__blacklists__from__file)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__set__custom__whitelists)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__set__custom__whitelists__from__file)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__start)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__start__disconnected)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__stop)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__threats__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__background__wait__for__connection)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__capture)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__check__policy)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__check__policy__for__domain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__check__policy__for__domain__with__signature)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__completion)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__foreground__start)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__get__core__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__get__core__version)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__get__device__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__get__score)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__get__system__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__get__tag__prefixes)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__get__threat__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__lanscan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__list__threats)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__merge__custom__whitelists)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__merge__custom__whitelists__from__files)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__remediate__all__threats)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__remediate__all__threats__force)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__remediate__threat)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__request__pin)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__request__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__request__signature)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__help__rollback__threat)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__lanscan)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__list__threats)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__merge__custom__whitelists)
            opts="-v -h --verbose --help <WHITELIST_JSON_1> <WHITELIST_JSON_2>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__merge__custom__whitelists__from__files)
            opts="-v -h --verbose --help <WHITELIST_FILE_1> <WHITELIST_FILE_2>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__remediate__all__threats)
            opts="-v -h --verbose --help [REMEDIATIONS]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__remediate__all__threats__force)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__remediate__threat)
            opts="-v -h --verbose --help <THREAT_ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__request__pin)
            opts="-v -h --verbose --help <USER> <DOMAIN>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__request__report)
            opts="-v -h --verbose --help <EMAIL> <SIGNATURE>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__request__signature)
            opts="-v -h --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        edamame_posture__rollback__threat)
            opts="-v -h --verbose --help <THREAT_ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _edamame_posture -o nosort -o bashdefault -o default edamame_posture
else
    complete -F _edamame_posture -o bashdefault -o default edamame_posture
fi
