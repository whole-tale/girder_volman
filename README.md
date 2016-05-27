BRIDGE_IP=$(docker inspect --format='{{.NetworkSettings.Networks.bridge.Gateway}}' tmpnb-proxy)

dockerun -d --privileged -v /var/run/docker.sock:/var/run/docker.sock \
  -p ${BRIDGE_IP}:9005:9005 -e CONFIGPROXY_AUTH_TOKEN="..." -v /:/host \
  --name volman xarthisius/volman
