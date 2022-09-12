#!/usr/bin/env bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  exec sudo /usr/bin/env bash "$0" "$@"
fi

declare -a peers=(1 2)
declare -a vanilla_wg_peers=(1)

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

get_ip() {
  echo "10.20.30.${1}/24"
}

get_port() {
  echo "$(( 56780 + $1 ))"
}

get_interface() {
  echo "wg${1}"
}

get_pk() {
  echo "${DIR}/fixtures/wg${1}.pub"
}

get_sk() {
  echo "${DIR}/fixtures/wg${1}.key"
}

start() {
  for i in "${vanilla_wg_peers[@]}"; do
    private_key="$(get_sk "$i")"
    public_key="$(get_pk "$i")"
    if ! [[ -f "${private_key}" ]] || ! [[ -f "$public_key" ]]; then
      wg genkey | (umask 0077 && tee "$private_key") | wg pubkey > "$public_key"
    fi
  done

  for i in "${vanilla_wg_peers[@]}"; do
    interface="$(get_interface "$i")"
    listening_port="$(get_port "$i")"
    private_key="$(get_sk "$i")"
    if command -v wireguard-go; then
      wireguard-go "$interface"
    else
      ip link add dev "${interface}" type wireguard
      ip addr add "$(get_ip "$i")" dev "$interface"
    fi
    wg set "$interface" listen-port "${listening_port}" private-key "${private_key}"
    for j in "${peers[@]}"; do
      if ! [[ "$i" == "$j" ]]; then
        wg set "$interface" peer "$(cat "$(get_pk "$j")")" endpoint 127.0.0.1:"$(get_port "$j")" allowed-ips "$(get_ip "$j" | awk -F/ '{print $1}')"
      fi
    done
    wg set "$interface" peer "$(cat "$(get_pk 0)")" allowed-ips 0.0.0.0/0
    ip link set "$interface" up
  done
  echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control
}

stop() {
  for i in "${vanilla_wg_peers[@]}"; do
    interface="$(get_interface "$i")"
    ip link set "$interface" down || true
    ip link delete dev "$interface" || true
  done
  echo module wireguard -p > /sys/kernel/debug/dynamic_debug/control
}

restart() {
    stop "$@"
    start "$@"
}

usage() {
  echo "$0 start|stop|restart"
  exit
}

if [[ $# -eq 0 ]]; then
  usage
fi

action="$1"
case "$action" in
start | stop | restart)
  shift
  "$action" "$@"
  ;;
*)
  usage
  ;;
esac
