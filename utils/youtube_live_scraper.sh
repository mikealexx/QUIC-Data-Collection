#!/bin/bash

# Default number of runs
RUN_TIMES=1
PYTHON_SCRIPT="utils/youtube_live_scraper.py"  # Change this to your Python file

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --run-times) RUN_TIMES="$2"; shift ;;  # Accepts --run-times
        --script) PYTHON_SCRIPT="$2"; shift ;;  # Optional: Specify a different script
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Validate RUN_TIMES is a positive integer
if ! [[ "$RUN_TIMES" =~ ^[0-9]+$ ]]; then
    echo "Error: --run-times must be a positive integer"
    exit 1
fi

# Run the Python script the specified number of times
for ((i=1; i<=RUN_TIMES; i++)); do
    echo "Running $PYTHON_SCRIPT ($i/$RUN_TIMES)..."
    python "$PYTHON_SCRIPT"
done

echo "Finished running $PYTHON_SCRIPT $RUN_TIMES times."