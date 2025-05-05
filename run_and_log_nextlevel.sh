#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
MAIN_SCRIPT_DIR="$HOME/Tools"
MAIN_SCRIPT_NAME="nextLevel3.sh"
LOG_REPO_DIR="$HOME/Tools/nextlevel3-logs"
LOG_FILE_NAME="nextLevel3-run.log"
DEFAULT_COMMIT_MSG="chore: add full ${MAIN_SCRIPT_NAME} run log"
# --- End Configuration ---

# --- Determine Full Paths ---
MAIN_SCRIPT_PATH="${MAIN_SCRIPT_DIR}/${MAIN_SCRIPT_NAME}"
LOG_FILE_PATH="${LOG_REPO_DIR}/${LOG_FILE_NAME}"

# --- Pre-checks ---
if [[ ! -f "$MAIN_SCRIPT_PATH" ]]; then
  echo "Error: Main script not found at ${MAIN_SCRIPT_PATH}"
  exit 1
fi
if [[ ! -d "$LOG_REPO_DIR" ]]; then
  echo "Error: Log repository directory not found at ${LOG_REPO_DIR}"
  exit 1
fi
# --- End Pre-checks ---

# --- Main Execution ---
echo "Attempting to refresh sudo credentials..."
sudo -v # Request sudo password upfront and cache it. Might still expire during long script run.

echo "Running ${MAIN_SCRIPT_NAME} from ${MAIN_SCRIPT_DIR}..."
echo "Output will be logged directly to: ${LOG_FILE_PATH}"

# Execute the main script from its directory to ensure relative paths work,
# but redirect stdout/stderr directly to the final log file path.
# The subshell ( ... ) contains the cd and execution.
(cd "$MAIN_SCRIPT_DIR" && "./$MAIN_SCRIPT_NAME" > "$LOG_FILE_PATH" 2>&1)

echo "${MAIN_SCRIPT_NAME} finished."
echo "Processing log file in Git repository: ${LOG_REPO_DIR}"

# Change to the log repository directory
cd "$LOG_REPO_DIR"

# Use commit message from the first argument, or default if not provided
COMMIT_MSG="${1:-$DEFAULT_COMMIT_MSG}"

echo "Adding log file (${LOG_FILE_NAME})..."
# Use -f (force) in case the log file is listed in .gitignore
git add -f "$LOG_FILE_NAME"

echo "Committing with message: '${COMMIT_MSG}'..."
git commit -m "$COMMIT_MSG"

echo "Pushing to remote..."
git push

echo "Workflow complete. Log pushed to repository."
# Optional: cd back to original directory if needed
# cd -