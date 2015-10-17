# PyCat
Python Net Tool

Pycat is a python replacement tool for netcat. That automatically scans for hosts that are up on the local network. Simply run PyCat.py without arguments to automatically start scanning the network. CTRL+C will interrupt scanning and display the options for interacting with hosts that are up. The options are as follows.

```
PyCat.py -h --help
Display this help message

PyCat.py -t target_host -p port

PyCat.py -l --listen
Listen on [host]:[port] for incoming connections

PyCat.py -c --command
Initialize a command shell

PyCat.py -e --execute=file_to_run
Execute file upon connection

PyCat.py -u --upload=destination
Upon connection upload file and write to [destination]
```

This tool was inspired by Black Hat Python and i plan on expanding it further in the future.
