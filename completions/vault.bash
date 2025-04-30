_python -m vault.cli_completion() {
    local IFS=$'\t'
    COMPREPLY=( $( env COMP_WORDS="${COMP_WORDS[*]}" \
                   COMP_CWORD=$COMP_CWORD \
                   _PYTHON _M VAULT.CLI_COMPLETE=complete-bash $1 ) )
    return 0
}

complete -F _python -m vault.cli_completion -o default python -m vault.cli
