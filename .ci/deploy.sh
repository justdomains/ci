#!/bin/bash
#
# Commit directory to GitHub repo
#

set -e # Exit with nonzero exit code if anything fails

# Requires the following environment variables to be set:
#   DEPLOY_BASE64_KEY_VAR=""   # The environment variable name that contains the base64-encoded ssh deploy (private) key
#   DEPLOY_REPO_SLUG=""        # The GitHub repo slug (user/repo) for the target (deployment) repo
#   DEPLOY_TARGET_BRANCH=""    # The target (deployment) repo branch
#   DEPLOY_GIT_NAME=""         # The name to be used for Git deployment commits
#   DEPLOY_GIT_EMAIL=""        # The email to be used for Git deployment commits

# Requires the following script input parameters:
#   $1 = the $SOURCE_DIR (i.e. the directory into which buildrepo.py output)

# Check if other required environment variables are set
if [ -z "$DEPLOY_BASE64_KEY_VAR" ]; then
	echo "Skipping deployment; DEPLOY_BASE64_KEY_VAR is not set."
	exit
fi
if [ -z "$DEPLOY_REPO_SLUG" ]; then
	echo "Skipping deployment; DEPLOY_REPO_SLUG is not set."
	exit
fi
if [ -z "$DEPLOY_TARGET_BRANCH" ]; then
	echo "Skipping deployment; DEPLOY_TARGET_BRANCH is not set."
	exit
fi
if [ -z "$DEPLOY_GIT_NAME" ]; then
	echo "Skipping deployment; DEPLOY_GIT_NAME is not set."
	exit
fi
if [ -z "$DEPLOY_GIT_EMAIL" ]; then
	echo "Skipping deployment; DEPLOY_GIT_EMAIL is not set."
	exit
fi
if [ -z "$1" ]; then
	echo "Missing required 1st input argument (SOURCE_DIR)."
	exit
fi

# Configuration
SSH_REPO="git@github.com:${DEPLOY_REPO_SLUG}.git"
SOURCE_DIR="$1"

if [ ! -d "$SOURCE_DIR" ]; then
	echo "Provided input parameter '$SOURCE_DIR' is not a valid directory."
	exit
fi


echo "Set up SSH"

# IMPORTANT: Turn off command traces while dealing with the private key
set +x

# Get the encrypted private key from the repo settings
echo ${!DEPLOY_BASE64_KEY_VAR} | base64 --decode > ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_rsa

# IMPORTANT: Anyone can read the build log, so it MUST NOT contain any sensitive data
# set -x # For now, do not re-enable

# Add GitHub's public key
echo "|1|qPmmP7LVZ7Qbpk7AylmkfR0FApQ=|WUy1WS3F4qcr3R5Sc728778goPw= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==" >> ~/.ssh/known_hosts


# Create a temporary directory in which to clone the destination repo branch
echo "Create temporary working directory"
REPO_NAME=$(basename $SSH_REPO)
TARGET_DIR=$(mktemp -d /tmp/$REPO_NAME.XXXX)

echo "git clone --branch ${DEPLOY_TARGET_BRANCH} ${SSH_REPO} ${TARGET_DIR}"
git clone --branch ${DEPLOY_TARGET_BRANCH} ${SSH_REPO} ${TARGET_DIR}

# Sync the output directory with the cloned repo branch
echo "Sync $SOURCE_DIR with the cloned deployment branch"
rsync -rt --delete --exclude=".git" "$SOURCE_DIR/" "$TARGET_DIR/"

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
	if [ -z "$TRAVIS_REPO_SLUG" ]; then
		COMMIT_MESSAGE="Built lists from ci/ commit: $REV"
	else
		COMMIT_MESSAGE="Built lists from ci/ commit: $TRAVIS_REPO_SLUG@$REV"
	fi
fi

# Commit all changes to the deployment repo
cd "$TARGET_DIR"
git config user.name "$DEPLOY_GIT_NAME"
git config user.email "$DEPLOY_GIT_EMAIL"
git add -A .
echo "Commit changes with message: '$COMMIT_MESSAGE'"
git commit --allow-empty -m "$COMMIT_MESSAGE"
echo "git push $SSH_REPO $DEPLOY_TARGET_BRANCH"
git push $SSH_REPO $DEPLOY_TARGET_BRANCH

echo "Deploy finished."
