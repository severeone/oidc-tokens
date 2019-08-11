#!/bin/bash
./gradlew clean
./gradlew jar
./gradlew install
./gradlew javadoc
./gradlew test
