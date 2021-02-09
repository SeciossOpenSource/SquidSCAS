#!/bin/sh

type=$1

host=`sed -n "s/^log_server = \(.*\)$/\1/p" /usr/local/etc/scas_scan.conf`
user=`sed -n "s/^log_user = \(.*\)$/\1/p" /usr/local/etc/scas_scan.conf`
data_dir=/data/cloud_discovery_swg/
log_dir=/var/log/squid/
clog_dir=/var/log/c-icap/

if [ "$type" = "log" ]; then
    file=access.log-`date '+%Y%m%d'`.gz
    if [ -f $log_dir$file ]; then
        scp $log_dir$file $user@$host:$data_dir`uname -n`-$file
    fi
fi

if [ "$type" = "c-icap_log" ]; then
    file=c-icap.log-`date '+%Y%m%d'`
    prefix=`uname -n`
    if [ -f ${clog_dir}${file}.gz ]; then
        old_files=`ssh ${user}@${host} ls ${data_dir}${prefix}-c-icap.log-* 2>/dev/null`
        rc=$?
        update=0
        if [ $rc -eq 2 ]; then
            update=1
        elif [ $rc -eq 0 ]; then
            exist=0
            for f in $old_files; do
                if [ $f = ${data_dir}${prefix}-${file} ]; then
                    exist=1
                else
                    ssh ${user}@${host} rm $f
                fi
            done
            if [ $exist -eq 0 ]; then
                update=1
            fi
        fi
        if [ $update -eq 1 ]; then
            scp ${clog_dir}${file}.gz ${user}@${host}:${data_dir}${prefix}-${file}.gz
            ssh ${user}@${host} gzip -d ${data_dir}${prefix}-${file}.gz
        fi
    fi
    file=c-icap.log
    scp ${clog_dir}${file} ${user}@${host}:${data_dir}${prefix}-${file}
fi

if [ "$type" = "conf" ]; then
    updated=0
    scp swg@$host:/data/cloud_discovery_swg/conf/* /etc/squid/tmp
    for file in `ls /etc/squid/tmp`; do
        if [ -n "`diff /etc/squid/$file /etc/squid/tmp/$file`" ]; then
            cp /etc/squid/tmp/$file /etc/squid
            updated=1
        fi
    done

    if [ $updated -gt 0 ]; then
        systemctl restart c-icap
        systemctl reload squid
    fi
fi
