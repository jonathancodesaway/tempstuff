#!/bin/bash

IFACE=$(ip route get 10.10.2.255 | head -n 1 | cut -d ' ' -f 4)

l_start=120
l_end=240

for i in {1..10}; do
	for(( l = ${l_start}; l<=${l_end}; l=l+5)); do
		if [ "$(hostname --short)" = "client" ]; then
			echo "START" | netcat router 8888
			echo "Sending traffic at rate $l ($i)"
			ITGSend -a server -l "sender-$l-$i.log" -x "receiver-$l-$i.log" -E "$l" -e 470 -T UDP -t 110000
		fi

		if [ "$(hostname --short)" = "router" ]; then
			netcat -l 8888 > /dev/null
			sleep 10
			bash queuemonitor.sh "$IFACE" 90 0.1 > "router-$l-$i.txt"
			echo -n "$l,$i,"
			cat "router-$l-$i.txt" | \
				sed 's/\p / /g' | \
				awk '{ sum += $37 } END { if (NR > 0) print sum / NR }'
		fi
	done
done

