# IO-Tracer

## How it works
Visit [IO Tracer documentations](https://cachemon.github.io/iotracerdocs/) for more detail.

## Installation
[Installation Guide](https://cachemon.github.io/iotracerdocs/startlinux/)

## Usage
```
usage: iotrc.py [-h] [-o OUTPUT] [-v VERBOSE] [-a] [-au]

Trace IO syscalls

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output Directory for logging, must be new!
  -v VERBOSE, --verbose VERBOSE
                        Print verbose output
  -a, --anonimize       Enable anonymization of process and file names
  -au, --auto-upload    Enable anonymization of process and file names
```

## Use as a service
We provided a simple bash script that installs and enable IO Traces as a service. Feel free to tinker with it and suit it to your best needs!

```
Usage: ./scripts/install_service.sh {--install|--uninstall|--status|--start|--stop|--restart|--logs}

Options:
  --install      Install and enable the service
  --uninstall    Stop and remove the service
  --status       Show service status
  --start        Start the service now
  --stop         Stop the service
  --restart      Restart the service
  --logs         View live service logs
