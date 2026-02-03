# uriosp

sudo usermod -aG uriosp "$USER"
newgrp uriosp

id | grep uriosp

sudo uriosp config <path/to/clouds.yaml>

sudo uriosp config duong.yaml
uriosp os token issue
uriosp os server list --all-projects


eval "$(uriosp auth)"
uriosp inventory
