#!/bin/bash

# inspired by http://eli.thegreenplace.net/2013/12/26/adding-bash-completion-for-your-own-tools-an-example-for-pss

_estail_complete()
{
    local cur_word prev_word prod_list app_list
    local ESTAIL_DOT_DIR=$HOME/.estail
    mkdir -p $ESTAIL_DOT_DIR
    local ESTAIL_PROD_LIST_FILE=$ESTAIL_DOT_DIR/products
    local ESTAIL_APPS_LIST_FILE=$ESTAIL_DOT_DIR/applications

    # COMP_WORDS is an array of words in the current command line.
    # COMP_CWORD is the index of the current word (the one the cursor is
    # in). So COMP_WORDS[COMP_CWORD] is the current word; we also record
    # the previous word here, although this specific script doesn't
    # use it yet.
    cur_word="${COMP_WORDS[COMP_CWORD]}"
    prev_word="${COMP_WORDS[COMP_CWORD-1]}"

    # generate a list
    NOW_EPOCH=`date +%s`
    FILE_EXPIRATION=`expr $NOW_EPOCH - 86400` # a day ago
    if [[ ! -s $ESTAIL_PROD_LIST_FILE ]] || [[ `stat ${ESTAIL_PROD_LIST_FILE} --printf="%Y"` < $FILE_EXPIRATION ]] ; then
        estail --list_products > $ESTAIL_PROD_LIST_FILE
    fi
    if [[ ! -s $ESTAIL_APPS_LIST_FILE ]] || [[ `stat ${ESTAIL_APPS_LIST_FILE} --printf="%Y"` < $FILE_EXPIRATION ]] ; then
        # estail --list already writes to $ESTAIL_APPS_LIST_FILE, we don't want to overwrite
        estail --list > /dev/null
    fi
    prod_list=`cat $ESTAIL_PROD_LIST_FILE`
    app_list=`cat $ESTAIL_APPS_LIST_FILE`
    option_list="-h --help -p --product -a --application --list -P --list_products --lookback "
    option_list+="-r --refresh -g --grep -f --follow -s --startdate -e --enddate --env -d --datacenter "
    option_list+="-H --hostname -n --log-events --verbose"

    # perform product completion if product flag was specified
    if [[ ${prev_word} == "-p" ]] || [[ ${prev_word} == "--product" ]] ; then
        COMPREPLY=( $(compgen -W "${prod_list}" -- ${cur_word}) )
    elif [[ ${prev_word} == "-a" ]] || [[ ${prev_word} == "--application" ]] ; then
        COMPREPLY=( $(compgen -W "${app_list}" -- ${cur_word}) )
    else
        COMPREPLY=( $(compgen -W "${option_list}" -- ${cur_word} ) )
    fi
    return 0
}

# Register _estail_complete to provide completion for the following commands
complete -F _estail_complete estail
