#!/usr/bin/env python3
#-*- coding: utf-8 -*-
from click import command
import frida
import codecs
import sys
import os
import subprocess
import signal

from frida.core import Script

dumped_files = set()
received_files = set()
loaded_classes = set()
loaded_methods = set()
loaded_files = set()

sample = None

def handler(signum, frame):
    global dumped_files
    global received_files
    global loaded_classes
    global loaded_methods
    global sample

    command_adb_pull = "adb pull %s %s/%s"

    print("\n\n")
    print("================== Report Summary ==================")

    if len(dumped_files) > 0:
        
        print("[!] DUMPED dex/apk files...")
        print("[+] The sample dumped %d APK/DEX files" % (len(dumped_files)))

        for file in dumped_files:
            file_name = os.path.basename(file)
            command = command_adb_pull % (file, sample, file_name)
            print("[+] Dumping file %s into %s/%s" % (file, sample, file_name))
            try:
                subprocess.check_output(command, shell=True)
            except Exception as e:
                print("[-] Not possible to dump '%s': %s" % (file, e))
    if len(received_files) > 0:
        print("[!] Files received from hooks:")
        for file in received_files:
            print("\t[+] %s" % (file))
    if len(loaded_classes) > 0:
        print("[!] Loaded classes: ")
        for loaded_class in loaded_classes:
            print("\t[+] %s" % (loaded_class))
    
    if len(loaded_methods) > 0:
        print("[!] Loaded methods: ")
        for loaded_method in loaded_methods:
            print("\t[+] %s" % (loaded_method))
 
    if len(loaded_files) > 0:
        print("[!] Loaded files in memory: ")
        for loaded_file in loaded_files:
            print("\t[+] %s" % (loaded_file))

    sys.exit(0)


def on_message(message, data):
    global dumped_files
    global loaded_classes
    global loaded_methods
    global sample
    global received_files
    #print(message)

    if "payload" in message:
        if "dumped_file" in message["payload"]:
            print("Received dumped file: %s" % (message["payload"]["dumped_file"]))
            if "content" in message["payload"]:
                file_name = os.path.basename(message["payload"]["dumped_file"])
                if os.path.exists("%s/%s" % (sample, file_name)):
                    return
                received_files.add(file_name)
                with open("%s/%s" % (sample, file_name), "wb") as f_:
                    content = bytearray(message["payload"]["content"]['data'])
                    f_.write(content)
            else:
                dumped_files.add(message["payload"]["dumped_file"])
        if "loaded_class" in message["payload"]:
            print("Received loaded class: %s" % (message["payload"]["loaded_class"]))
            loaded_classes.add(message["payload"]["loaded_class"])
        if "loaded_method" in message["payload"]:
            print("Received loaded method: %s" % (message["payload"]["loaded_method"]))
            loaded_methods.add(message["payload"]["loaded_method"])
        if "loaded_file" in message['payload']:
            print("Received loaded file: %s" % (message['payload']['loaded_file']))
            loaded_files.add(message['payload']['loaded_file'])


def main(argv):
    global sample
    signal.signal(signal.SIGINT, handler)

    if len(argv) < 2:
        print("[-] Usage: frida_vm_hooking.py <package_name> <script_to_load>")
        sys.exit(1)
    
    package_name = str(argv[0])
    frida_script = str(argv[1])
    sample = package_name

    if not os.path.exists(sample):
        os.mkdir(sample)

    if not os.path.isfile(frida_script):
        print("[-] Frida script '%s' provided was not found" % (frida_script))
        sys.exit(1)
    
    # get an emulator instance for analysis
    device = frida.get_usb_device(timeout=20)
    # start the process given its package name
    pid = device.spawn(package_name)
    # now attach to the pid of the process
    # then we will load it
    session = device.attach(pid)

    print("[+] Attached to device, installing hooks in: %d" % (int(pid)))

    script_code = codecs.open(frida_script, 'r', encoding='utf8')

    hook = session.create_script(script_code.read())

    hook.on('message', on_message)

    print("[+] Added new hook script: %s" % (frida_script))

    hook.load()

    device.resume(pid)

    sys.stdin.read()

if __name__ == "__main__":
    main(sys.argv[1:])
    sys.exit(0)