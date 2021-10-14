#!/bin/bash

function nsenter-ctn () {
    CTN=$1 # Container ID or name
    PID=$(sudo docker inspect --format "{{.State.Pid}}" $CTN)
    shift 1 # Remove the first arguement, shift remaining ones to the left
    sudo nsenter -t $PID $@
}
