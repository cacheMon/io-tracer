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
    echo "  -d,     --duration <seconds>    Duration to trace, including compiling (default: 30 seconds)"
    echo "  -o,     --output <directory>    Output directory (default: vfs_trace_analysis_timestamp)"
    # echo "  -l, --limit <count>        Limit number of events to capture (default: unlimited)"
    # echo "  -p, --pid <pid>            Filter tracing to specific PID"
    # echo "  -w, --workload <command>   Run a specific workload while tracing"
    echo "  -v,     --verbose               Log outputs"
    echo "  -h,     --help                  Show this help message"
    echo "  -tw,    --time-window',         Time window for matching PIDs (default 5_000_000 ns)"
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
        -tw|--time-window)
            TIME_WINDOW="$2"
            shift 2
            ;;
        # -w|--workload)
        #     WORKLOAD="$2"
        #     shift 2
        #     ;;
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

# TODO Update BPF file with PID filter if specified
# if [ -n "$PID" ]; then
#     echo "Filtering trace to PID $PID"
#     cp vfs_prober.c "$OUTPUT_DIR/vfs_prober_tmp.c"
#     sed -i "s/FILTER_PID/$PID/" "$OUTPUT_DIR/vfs_prober_tmp.c"
#     BPF_FILE="$OUTPUT_DIR/vfs_prober_tmp.c"
# else
#     BPF_FILE="vfs_prober.c"
# fi
BPF_FILE="./tracer/vfs_prober.c"

# # Trace VFS calls
# LOG_FILE="$OUTPUT_DIR/vfs_trace.log"
# JSON_FILE="$OUTPUT_DIR/vfs_trace.json"

# echo "Starting VFS trace for $DURATION seconds..."
# echo "Output will be saved to $OUTPUT_DIR"

# TODO Limit output
# if [ $LIMIT -gt 0 ]; then
#     python3 iotracer.py -o "$LOG_FILE" -j "$JSON_FILE" -l $LIMIT -b "$BPF_FILE" &
# else
#     python3 iotracer.py -o "$LOG_FILE" -j "$JSON_FILE" -b "$BPF_FILE" &
# fi

PARAMS="-b \"$BPF_FILE\""

if [ -v OUTPUT_DIR ] || [ -n "$OUTPUT_DIR" ]; then
    PARAMS="$PARAMS -o \"$OUTPUT_DIR\""
fi

if [ -v DURATION ] || [ -n "$DURATION" ]; then
    PARAMS="$PARAMS -d $DURATION"
fi

if [ -v TIME_WINDOWN ] || [ -n "$TIME_WINDOW" ]; then
    PARAMS="$PARAMS -tw $TIME_WINDOW"
fi

if [ $VERBOSE -eq 1 ]; then
    echo "Verbose mode enabled"
    PARAMS="$PARAMS -v True"
    eval "python ./tracer.py $PARAMS"
else
    echo "Verbose mode disabled"
    echo "python ./tracer.py $PARAMS"
    eval "python3 ./tracer.py $PARAMS"
fi

# if [ $LIMIT -eq 0 ]; then
#     echo "Tracing for $DURATION seconds..."
#     sleep $DURATION
#     echo "Stopping tracer..."
#     kill -SIGINT $TRACER_PID
    
#     # Stop workload if it's still running
#     if [ -n "$WORKLOAD_PID" ] && kill -0 $WORKLOAD_PID 2>/dev/null; then
#         echo "Stopping workload..."
#         kill -SIGTERM $WORKLOAD_PID
#     fi
# else
#     # code unreachable
#     # TODO: implement limit
#     echo "Tracing until $LIMIT events are captured..."
#     wait $TRACER_PID
    
#     # Stop workload if it's still running
#     if [ -n "$WORKLOAD_PID" ] && kill -0 $WORKLOAD_PID 2>/dev/null; then
#         echo "Stopping workload..."
#         kill -SIGTERM $WORKLOAD_PID
#     fi
# fi

# start the analyzer
# echo "====================== Running analysis on trace data... ======================"
./venv/bin/python ./analyzer.py "$OUTPUT_DIR/trace.log" -o "$OUTPUT_DIR/analysis"

# echo "Analysis complete. Results are in $OUTPUT_DIR/analysis/"
# echo "Charts are in $OUTPUT_DIR/analysis/charts/"

# if [ -f "$OUTPUT_DIR/analysis/summary_stats.txt" ]; then
#     echo "-------------------------------------------------------------"
#     echo "VFS Trace Summary:"
#     echo "-------------------------------------------------------------"
#     cat "$OUTPUT_DIR/analysis/summary_stats.txt"
#     echo "-------------------------------------------------------------"
# else
#     echo "-------------------------------------------------------------"
#     echo "VFS Trace Summary:"
#     echo "-------------------------------------------------------------"
#     echo "Total operations: $(grep -c "\[" "$LOG_FILE")"
#     echo "READ operations: $(grep -c "READ:" "$LOG_FILE")"
#     echo "WRITE operations: $(grep -c "WRITE:" "$LOG_FILE")"
#     echo "OPEN operations: $(grep -c "OPEN:" "$LOG_FILE")"
#     echo "CLOSE operations: $(grep -c "CLOSE:" "$LOG_FILE")"
#     echo "FSYNC operations: $(grep -c "FSYNC:" "$LOG_FILE")"
#     echo "-------------------------------------------------------------"
#     echo "Top accessed files:"
#     grep -o "file '[^']*'" "$LOG_FILE" | sort | uniq -c | sort -nr | head -5
#     echo "-------------------------------------------------------------"
# fi