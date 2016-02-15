#!/bin/bash

## Execute command on a circle node
#    1) On the node when circle node == current step
#    2) On the given node when the first argument is number.
#
step() {
  if [ $1 -ge 0 ] 2>/dev/null; then
    # execute step only on the given node
    node_num=$1; shift
  else
    # execute step on the current node
    node_num=${extCIRCLE_STEPNUM:=0}
    export extCIRCLE_STEPNUM
  fi

  # Early step fail, because step is a part of composed command,
  # further execution doesn't make sense.
  set -e

  if [ $node_num = $CIRCLE_NODE_INDEX ]; then
    # Execute command (which is all args passed to the function)
    echo "Executing command: \`$@' ..."
    $@
  fi
}

## Switch command execution to the next circle node.
#  We can switch to the next node or directly to the specific node
#  if the first argument is number.
next() {
  if [ -z "$1" ]; then
    step_num=${extCIRCLE_STEPNUM:-0}
    step_num=$((step_num+1))
  else
    step_num=$1
  fi
  export extCIRCLE_STEPNUM=$step_num
}
