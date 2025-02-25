#!/bin/bash

# Default values
INPUT_DIR=""
OUTPUT_DIR=""
TYPE_FILE=""

# Parse named arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --input-dir) INPUT_DIR="$2"; shift ;;
        --output-dir) OUTPUT_DIR="$2"; shift ;;
        --type-file) TYPE_FILE="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Ensure required arguments are provided
if [[ -z "$INPUT_DIR" || -z "$OUTPUT_DIR" || -z "$TYPE_FILE" ]]; then
    echo "Usage: $0 --input-dir <input_directory> --output-dir <output_directory> --type-file <type.json>"
    exit 1
fi

# Ensure directories exist
if [[ ! -d "$INPUT_DIR" ]]; then
    echo "Error: Input directory '$INPUT_DIR' not found!"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"  # Create output directory if it doesn't exist

# Ensure type.json exists
if [[ ! -f "$TYPE_FILE" ]]; then
    echo "Error: Type file '$TYPE_FILE' not found!"
    exit 1
fi

# Process each JSON file in the input directory
for FILE in "$INPUT_DIR"/*.json; do
    # Skip type.json if it's in the input directory
    [[ "$FILE" == "$TYPE_FILE" ]] && continue 

    FILENAME=$(basename "$FILE")
    OUTPUT_FILE="$OUTPUT_DIR/$FILENAME"
    OUTPUT_FILE=$(echo "$OUTPUT_FILE" | sed -E 's/dvt-keygen-[0-9a-f]+-//')
    jq --slurpfile type "$TYPE_FILE" '{params: $type[0], scenario: .}' "$FILE" > "$OUTPUT_FILE"

    echo "Processed: $FILE -> $OUTPUT_FILE"
done

echo "Processing complete. Files saved in $OUTPUT_DIR."
