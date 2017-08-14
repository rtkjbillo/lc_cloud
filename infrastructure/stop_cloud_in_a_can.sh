#! /bin/bash

echo "Shutting down Beach..."

pkill -f -x "python.*(/beach/|limacharlie).*"

beachDone=0
retry=0

until [ $beachDone -eq 1 ]
do
	ps -elf | grep -E "python.*(/beach/|limacharlie).*" | grep -v grep > /dev/null
	beachDone=$?
	retry=`expr $retry + 1`
	if [ $beachDone -eq 1 ] ; then
		break
	fi
	if [ $retry -eq 20 ] ; then
		echo "Timed out waiting for Beach to shutdown, killing it."
		pkill -9 -f -x "python.*(/beach/|limacharlie).*"
	fi
	echo "...waiting..."
	sleep 1
done

echo "Beach shut down."
