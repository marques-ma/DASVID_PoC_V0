#!/bin/bash
kill -9 $(ps -ef | grep "spire-agent" | grep -v grep | awk '{print $2}')
kill -9 $(ps -ef | grep "spire-server" | grep -v grep | awk '{print $2}')
rm -rf /spire/.data

spire-server run -config /spire/conf/server/server.conf &
sleep 3

tmp=$( spire-server token generate -spiffeID spiffe://example.org/host)
echo $tmp
token=${tmp:7}
spire-agent run -joinToken $token -config /spire/conf/agent/agent.conf &
sleep 3

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/asserting_wl \
    -selector docker:label:type:assertingwl