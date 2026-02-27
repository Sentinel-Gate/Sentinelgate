# Makefile for TLA+ model checking of the SentinelGate PolicyEngine spec.
#
# Prerequisites: Java (JDK or JRE) on PATH.
#
# Usage:
#   make download   # download tla2tools.jar
#   make check      # run TLC model checker
#   make clean      # remove generated artifacts

TLA2TOOLS_VERSION := 1.8.0
TLA2TOOLS_JAR := tla2tools.jar
TLA2TOOLS_URL := https://github.com/tlaplus/tlaplus/releases/download/v$(TLA2TOOLS_VERSION)/tla2tools.jar

JAVA := java
JAVA_OPTS := -XX:+UseParallelGC
TLC_OPTS := -workers auto -deadlock

.PHONY: all check clean download

all: check

download: $(TLA2TOOLS_JAR)

$(TLA2TOOLS_JAR):
	curl -fSL -o $@ $(TLA2TOOLS_URL)

check: $(TLA2TOOLS_JAR)
	$(JAVA) $(JAVA_OPTS) -cp $(TLA2TOOLS_JAR) tlc2.TLC MC_PolicyEngine -config PolicyEngine.cfg $(TLC_OPTS)

clean:
	rm -rf $(TLA2TOOLS_JAR) *.out states/
