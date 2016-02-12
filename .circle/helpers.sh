#!/bin/bash

## Execute command on circle node, which curresponds to the current step number
#
step() {
  : ${extCIRCLE_STEPNUM:=0}
  export extCIRCLE_STEPNUM

  # Early step fail, because step is a part of composed command,
  # further execution doesn't make sense.
  set -e

  if [ $extCIRCLE_STEPNUM = $CIRCLE_NODE_INDEX ]; then
    # Execute command (which is all args passed to the function)
    echo "Executing command: \`$@' ..."
    $@
  fi
}

## Switch command execution to the next circle node.
#
next() {
  : ${extCIRCLE_STEPNUM:=0}
  export extCIRCLE_STEPNUM
  extCIRCLE_STEPNUM=$((extCIRCLE_STEPNUM+1))
}
