#!/bin/bash

# Configuration
MAX_ERROR_BLOCKS=10  # Number of iterations to run with max-blocks = 1
SLEEP_TIME=10       # Sleep time in seconds

# State variables
error_counter=0     # Counts how many times to use the error setting

echo "Starting synchronized cargo run loop..."

while true; do
    
    # --- Determine Arguments ---
    if [ $error_counter -gt 0 ]; then
        # Running in error-mitigation mode
        MAX_BLOCKS_ARG=1
        echo "Error detected previously. Running with --max-blocks $MAX_BLOCKS_ARG. ($error_counter iterations left)"
        error_counter=$((error_counter - 1))
    else
        # Running in normal mode
        MAX_BLOCKS_ARG=10
        echo "Running with --max-blocks $MAX_BLOCKS_ARG."
    fi

    # --- Execute Command ---
    # The full command is executed, and its exit code ($?) is checked immediately after.
    cargo run --features tx_v6 -- sync --network ztarknet --fee 76000000 --max-blocks $MAX_BLOCKS_ARG
    EXIT_CODE=$?

    # --- Check for Error and Update State ---
    if [ $EXIT_CODE -ne 0 ]; then
        echo "🚨 cargo run failed with exit code $EXIT_CODE."
        
        # Only switch to error mode if we're not already in it (i.e., counter is 0)
        if [ $error_counter -eq 0 ]; then
            echo "Switching to error-mitigation mode: setting --max-blocks to 1 for $MAX_ERROR_BLOCKS iterations."
            error_counter=$MAX_ERROR_BLOCKS
        else
            echo "Already in error-mitigation mode. Remaining iterations: $error_counter."
        fi
    fi

    # --- Wait for Next Iteration ---
    echo "Sleeping for $SLEEP_TIME seconds..."
    sleep $SLEEP_TIME
    
done

# The script should never reach here in the current logic.