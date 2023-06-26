#!/bin/bash
#
# Run SparForte SDL examples using an X-Windows frame buffer so as to test
# on systems without a desktop (e.g. Jenkins)
#
# Ken Burtch
# ----------------------------------------------------------------------------
shopt -s -o nounset

declare -i RESULT=0    # shell return status code
declare -i XVFB_PID=0  # Xvfb process id
# set +x

# Check to see if Xfvb is running on DISPLAY 98
# Otherwise, start it with the given display specifications and get the
# process id.

if [ -f "/tmp/.X98-lock" ] ; then
   echo "ERROR: Xvfb is running already"
   RESULT=1
else
   /usr/bin/Xvfb ":98" -screen 0 1024x768x16 &
   RESULT=$?
   if [ $RESULT -eq 0 ] ; then
      XVFB_PID=$!
      #echo "Xvfb PID: $XVFB_PID"
   fi
fi

# If Xvfb is running, run the example programs.  If any program should
# fail, skip the rest.  At the end, shut down the frame buffer.

if [ $XVFB_PID -ne 0 ] ; then
   # export DISPLAY=":98"
   export DISPLAY="127.0.0.1:98.0"
   /usr/local/bin/spar graph_series $@
   RESULT=$?
   #echo "Shutting down Xvfb PID: $XVFB_PID"
   kill $XVFB_PID
fi

exit $RESULT

