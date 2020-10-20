#!/bin/sh

#
# Based on ${JBOSS_HOME}/bin/elytron-tool.sh, modified to include add-on
# and run the retriever main class.
#
# To use this script, copy it to ${JBOSS_HOME}/bin/elytron-retriever.sh and
# also copy the retriever jar file to ${JBOSS_HOME}/bin/brambolt-rt-wildfly-elytron.jar.
#
# When copying the jar file, the version should be removed (it will still be
# present in the jar manifest). Make sure the jar file is compatible with the
# JBoss version it is being copied into.
#
# Then create a store like this:
#
#   cd ${JBOSS_HOME}
#   ./bin/elytron-tool.sh credential-store -l /tmp/elly.store -p elly.password -c
#   ./bin/elytron-tool.sh credential-store -l /tmp/elly.store -p elly.password -a elly.alias -x elly.secret
#
# And then you can retrieve the secret like this:
#
#   cd ${JBOSS_HOME}
#   ./bin/elytron-retriever.sh credential-store -l /tmp/elly.store -p elly.password -g elly.alias
#

DIRNAME=$(dirname "$0")

cygwin=false;
case "$(uname)" in
  CYGWIN*)
    cygwin=true
    ;;
esac

if $cygwin ; then
  # Ensure paths are in UNIX format:
  [ -n "$JBOSS_HOME" ] &&
    JBOSS_HOME=$(cygpath --unix "$JBOSS_HOME")
  [ -n "$JAVA_HOME" ] &&
    JAVA_HOME=$(cygpath --unix "$JAVA_HOME")
  [ -n "$JAVAC_JAR" ] &&
    JAVAC_JAR=$(cygpath --unix "$JAVAC_JAR")
fi

# Setup JBOSS_HOME:
RESOLVED_JBOSS_HOME=$(cd "$DIRNAME/.." || exit ; pwd)
if [ "x$JBOSS_HOME" = "x" ]; then
  JBOSS_HOME=${RESOLVED_JBOSS_HOME}
else
 SANITIZED_JBOSS_HOME=$(cd "$JBOSS_HOME" || exit ; pwd)
 if [ "$RESOLVED_JBOSS_HOME" != "$SANITIZED_JBOSS_HOME" ]; then
   echo "WARNING JBOSS_HOME may be pointing to a different installation - unpredictable results may occur."
   echo ""
 fi
fi
export JBOSS_HOME

# Setup the JVM:
if [ "x${JAVA}" = "x" ]; then
  if [ "x${JAVA_HOME}" != "x" ]; then
    JAVA="${JAVA_HOME}/bin/java"
  else
    JAVA="java"
  fi
fi

# For Cygwin, switch paths to Windows format before running java:
if $cygwin; then
  JBOSS_HOME=$(cygpath --path --windows "$JBOSS_HOME")
fi

BRAMBOLT_ADDON="${JBOSS_HOME}/bin/brambolt-rt-wildfly-elytron.jar"
ELYTRON_TOOL="${JBOSS_HOME}/bin/wildfly-elytron-tool.jar"
ELYTRON_TOOL_SEP=:

if [ "x$ELYTRON_TOOL_ADDONS" != "x" ]; then
  ELYTRON_TOOL_ADDONS="${BRAMBOLT_ADDON}${ELYTRON_TOOL_SEP}${ELYTRON_TOOL_ADDONS}"
else
  ELYTRON_TOOL_ADDONS=${BRAMBOLT_ADDON}
fi

CLASSPATH=\"${ELYTRON_TOOL}${ELYTRON_TOOL_SEP}${ELYTRON_TOOL_ADDONS}\"

eval \"$JAVA\" \
  "$JAVA_OPTS" \
  -cp "${CLASSPATH}" \
  com.brambolt.wildfly.security.tool.ElytronRetriever \
   '$0 "$@"'
