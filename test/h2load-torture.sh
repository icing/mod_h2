#!/bin/bash

URL='https://cgi.tests.httpd.apache.org:5001/h2proxy/h2test/error?body_delay=10ms'

while true; do
 /opt/quic/bin/h2load --connect-to=localhost:5001 -n 100000 -m 100 -c 64 "$URL" &
 H2PID=$!
 if false; then
   sec=$(( RANDOM%10))
   msec=$(( RANDOM%1000))
   sleep_time="${sec}.${msec}"
   sleep $sleep_time
   kill $H2PID
   echo "killed $H2PID after $sleep_time"
 else
   wait $H2PID
   echo "h2load $H2PID done."
 fi
done
