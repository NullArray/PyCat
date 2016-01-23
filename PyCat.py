#!/usr/bin/env python
# PyCat is a python replacement for Netcat

import sys
import socket
import getopt
import threading
import subprocess
import os
import struct

from netaddr import IPNetwork, IPAddress
from ctypes import *

# Define global variables
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0


# Usage/Help function
def usage():

    # Help text
    print
    print "Usage: PyCat.py -t target_host -p port"
    print
    print "-h --help"
    print "Display this help message"
    print
    print "-l --listen"
    print "Listen on [host]:[port] for incoming connections"
    print
    print "-c --command"
    print "Initialize a command shell"
    print
    print "-e --execute=file_to_run"
    print "Execute file upon connection"
    print
    print "-u --upload=destination"
    print "Upon connection upload file and write to [destination]"
    print
    print "Examples: "
    print "PyCat.py -t 192.168.0.1 -p 5555 -l -c"
    print "PyCat.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe"
    print "Pycat.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
    print "echo 'ABCDEFGHI' | ./PyCat.py -t 192.168.11.12 -p 135"
    sys.exit(0)


def scan():
    # ASCII Logo
    print '8888888b.          .d8888b.          888     '
    print '888   Y88b        d88P  Y88b         888_    '
    print '888    888        888    888         888     '
    print '888   d88P888  888888         8888b.  888888 '
    print '8888888P" 888  888888           "88b8 88     '
    print '888       888  888888    888. d888888 888    '
    print '888       Y88b 888Y88b  d88P 888  888 Y88b.  '
    print '888        "Y88888 "Y8888P"  "Y888888  "Y888 '
    print '               888                           '
    print '          Y8b d88P                           '
    print '           "Y88P"                            '
    # ASCII Logo
    print
    print
    print "Welcome to PyCat Net Tool"
    print
    print "The program will now scan the local network."
    print "Hit CTRL+C to interrupt scanning and to proceed to display"
    print "options for interacting with hosts that are up."
    print
    print "[+]Scanning the local network."
    import scanner
    run = scanner.Scan
    run
    print "[+]Scanning completed."
    usage()


def client_sender(buffer):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to target host
        client.connect((target, port))
        # Check for input from stdin, if input is present send to remote target
        if len(buffer):
            client.send(buffer)

        # Recieve data back until there is no more data to recieve
        while True:

            # Wait for data response
            recv_len = 1
            response = ""

            while recv_len:

                data = client.recv(4096)
                recv_len = len(data)
                response += data

                if recv_len < 4096:
                    break

            print response,

            # Wait for more input
            buffer = raw_input("")
            buffer += "\n"

            # Send it off (Loop)
            client.send(buffer)

    except:
        print "[!] Exception, exiting."

        # Close connection
        client.close()


# Primary server loop and stub function to handle command execution and command shell
def server_loop():
    global target

    # If no target is specified, we listen on all interfaces
    if not len(target):
        target = "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))

    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # Spin off a thread to handle new client
        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()


def run_command(command):
    # Trim the new line
    command = command.rstrip()

    # Run command and retrieve output
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except:
        output = "Failed to execute command. \r\n"

    # Send output back to the client
    return output


def client_handler(client_socket):
    global upload
    global execute
    global command

    # Check for upload
    if len(upload_destination):
        # Read in all of the bytes and write to out destination
        file_buffer = ""
        # Keep reading data until none is available
        while True:
            data = client_socket.recv(1024)

            if not data:
                break
            else:
                file_buffer += data
        # Now we take these bytes and try to write them out
        try:
            file_descriptor = open(upload_destination, "wb")
            file_descriptor.write(file_buffer)
            file_descriptor.close()

            # Acknowledge that we wrote the file out
            client_socket.send("Succesfully saved file to %s\r\n" % upload_destination)
        except:
            client_socket.send("Failed to save file to %s\r\n" % upload_destination)

    if len(execute):
        # Run the command
        output = run_command(execute)

        client_socket.send(output)

    # Start another loop if command shell was requested
    if command:

        while True:
            # Show prompt
            client_socket.send("<Shell:#> ")

            # Now we recieve until we see a linefeed (enter key)
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            # Send back the command output
            response = run_command(cmd_buffer)

            # Send the response back
            client_socket.send(response)


# Main funtion
def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    # Check if args are passed
    if not len(sys.argv[1:]):
        scan()

    # Read commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu", [
                                   "help", "listen", "execute", "target", "port", "command", "upload"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--command"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"

    # Are we going to listen or just send data from stdin?
    if not listen and len(target) and port > 0:

        # Read in the buffer from the commandline, this will block, so send CTRL-D
        # if not sending input to stdin
        buffer = sys.stdin.read()

        # Send data off
        client_sender(buffer)

    # We are going to listen and potentially upload things, execute commands and drop a shell back -
    # depending on the above commandline options
    if listen:
        server_loop

main()
