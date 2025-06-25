#!/bin/bash

# DURATION=30
OUTPUT_DIR="result/IO_trace_analysis_$(date +%Y%m%d_%H%M%S)"
LIMIT=0
PID=""
WORKLOAD=""
VERBOSE=0

function print_usage {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -d,     --duration <seconds>        Duration to trace, including compiling (default: 30 seconds)"
    echo "  -o,     --output <directory>        Output directory (default: vfs_trace_analysis_timestamp)"
    echo "  -v,     --verbose                   Log outputs"
    echo "  -h,     --help                      Show this help message"
    echo "  -tw,    --time-window,              Time window for matching PIDs (default 5_000_000 ns)"
    echo "  -f,    --flush_interval,            Buffered flush threshold in array length (default 5000)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -tw|--flush_interval)
            TIME_WINDOW="$2"
            shift 2
            ;;
        -f|--time-window)
            FLUSH_INTERVAL="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            echo "Verbose mode enabled"
            shift 1
            ;;
        -h|--help)
            print_usage
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            ;;
    esac
done

BPF_FILE="./src/tracer/prober/vfs_prober.c"


PARAMS="-b \"$BPF_FILE\""

if [ -v OUTPUT_DIR ] || [ -n "$OUTPUT_DIR" ]; then
    PARAMS="$PARAMS -o \"$OUTPUT_DIR\""
fi

if [ -v DURATION ] || [ -n "$DURATION" ]; then
    PARAMS="$PARAMS -d $DURATION"
fi

if [ -v TIME_WINDOW ] || [ -n "$TIME_WINDOW" ]; then
    PARAMS="$PARAMS -tw $TIME_WINDOW"
fi

if [ -v FLUSH_INTERVAL ] || [ -n "$FLUSH_INTERVAL" ]; then
    PARAMS="$PARAMS -f $FLUSH_INTERVAL"
fi

if [ $VERBOSE -eq 1 ]; then
    echo "Verbose mode enabled"
    PARAMS="$PARAMS -v True"
    eval "python ./iotrc.py $PARAMS"
else
    echo "Verbose mode disabled"
    echo "python ./iotrc.py $PARAMS"
    eval "python3 ./iotrc.py $PARAMS"
fi

echo "====================== Running analysis on trace data... ======================"
./venv/bin/python ./iotrcanalyze.py "$OUTPUT_DIR/trace.log" -o "$OUTPUT_DIR/analysis"