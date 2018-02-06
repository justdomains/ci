#!/bin/bash
#
# Commit directory to GitHub repo
#

set -e # Exit with nonzero exit code if anything fails

# Requires the following environment variables to be set:
#   DEPLOY_BRANCH =""          # The only branch from which Travis should deploy
#   DEPLOY_BASE64_KEY_VAR=""   # The Travis-CI environment variable name that contains the base64-encoded ssh deploy (private) key
#   DEPLOY_REPO_SLUG=""        # The GitHub repo slug (user/repo) for the target (deployment) repo
#   DEPLOY_TARGET_BRANCH=""    # The target (deployment) repo branch
#   DEPLOY_GIT_NAME=""         # The name to be used for Git deployment commits
#   DEPLOY_GIT_EMAIL=""        # The email to be used for Git deployment commits

# Requires the following script input parameters:
#   $1 = the $SOURCE_DIR (i.e. the directory into which buildrepo.py output)

if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
	echo "Skipping deployment from pull request."
	exit
fi

if [ -z $DEPLOY_BRANCH ]; then
	echo "Skipping deployment; DEPLOY_BRANCH is not set."
	exit
fi

if [ "$TRAVIS_BRANCH" != "$DEPLOY_BRANCH" ]; then
	echo "Skipping deployment; TRAVIS_BRANCH ('$TRAVIS_BRANCH') does not match DEPLOY_BRANCH ('$DEPLOY_BRANCH')."
	exit
fi

# Check if other required environment variables are set
if [ -z $DEPLOY_BASE64_KEY_VAR ]; then
	echo "Skipping deployment; DEPLOY_BASE64_KEY_VAR is not set."
	exit
fi
if [ -z $DEPLOY_REPO_SLUG ]; then
	echo "Skipping deployment; DEPLOY_REPO_SLUG is not set."
	exit
fi
if [ -z $DEPLOY_TARGET_BRANCH ]; then
	echo "Skipping deployment; DEPLOY_TARGET_BRANCH is not set."
	exit
fi
if [ -z $DEPLOY_GIT_NAME ]; then
	echo "Skipping deployment; DEPLOY_GIT_NAME is not set."
	exit
fi
if [ -z $DEPLOY_GIT_EMAIL ]; then
	echo "Skipping deployment; DEPLOY_GIT_EMAIL is not set."
	exit
fi
if [ -z "$1" ]; then
	echo "Missing required 1st input argument (SOURCE_DIR)."
	exit
fi

# Configuration
$SSH_REPO=git@github.com:${DEPLOY_REPO_SLUG}.git
$SOURCE_DIR=$1

if [ ! -d "$SOURCE_DIR" ]; then
	echo "Provided input parameter '$SOURCE_DIR' is not a valid directory."
	exit
fi

# IMPORTANT: Turn off command traces while dealing with the private key
set +x

# Get the encrypted private key from the repo settings
echo ${!DEPLOY_BASE64_KEY_VAR} | base64 --decode > ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_rsa

# IMPORTANT: Anyone can read the build log, so it MUST NOT contain any sensitive data
set -x

# Create a temporary directory in which to clone the destination repo branch
REPO_NAME=$(basename $SSH_REPO)
TARGET_DIR=$(mktemp -d /tmp/$REPO_NAME.XXXX)
git clone --branch ${DEPLOY_TARGET_BRANCH} ${SSH_REPO} ${TARGET_DIR}

# Sync the output directory with the cloned repo branch
rsync -rt --delete --exclude=".git" $SOURCE_DIR/ $TARGET_DIR/

# Build the commit message
COMMIT_MESSAGE=""
if [ "$TRAVIS_EVENT_TYPE" == "cron" ]; then
	DATE=`date +%Y-%m-%d`
	COMMIT_MESSAGE="Scheduled lists build: $DATE"
elif [ "$TRAVIS_EVENT_TYPE" == "api" ]; then
	DATE=`date +%Y-%m-%d`
	COMMIT_MESSAGE="Requested lists build: $DATE"
else
	REV=$(git rev-parse HEAD)
	COMMIT_MESSAGE="Built lists from ci/ commit: $REV"
fi

# Commit all changes to the deployment repo
cd $TARGET_DIR
git config user.name "$DEPLOY_GIT_NAME"
git config user.email "$DEPLOY_GIT_EMAIL"
git add -A .
git commit --allow-empty -m "$COMMIT_MESSAGE"
git push $SSH_REPO $DEPLOY_TARGET_BRANCH

echo "Deploy finished."