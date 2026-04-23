#!/bin/sh
wget -qO- "http://localhost:35001/vpn-event?status=connected" || true
