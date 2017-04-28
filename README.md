# PyCat
Python Net Tool

PyCat is a python replacement tool for netcat. That automatically scans for hosts that are up on the local network. Simply run PyCat.py without arguments to automatically start scanning the network. CTRL+C will interrupt scanning and display the options for interacting with hosts that are up.

# Update

I've added a timer set to 15 seconds on the main loop in scanner.py so that even if the scanner can't detect anything on the subnet or we are unable to send CTRL+C; e.g. we have PyCat on a remote server and can't send a keyboard interrupt through our shell, the program won't be scanning indefinitely and will automatically continue with it's normal operation.


# Usage

The options to use PyCat are as follows.

```
PyCat.py -h --help
Display this help message

PyCat.py -l --listen
Listen on [host]:[port] for incoming connections

PyCat.py -c --command
Initialize a command shell

PyCat.py -e --execute=file_to_run
Execute file upon connection

PyCat.py -u --upload=destination
Upon connection upload file and write to [destination]
```

The target host and port can be specified with the -t and -p options respectively as shown in the example below.
```
PyCat.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe
```

This tool was by in large inspired by Black Hat Python and i might expand on it's functionality in the future.
