#!/bin/bash
export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
/opt/gradle/gradle-8.6/bin/gradle "$@"
