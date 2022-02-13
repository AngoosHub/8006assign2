#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8006 Network Security & Applications Development
Assignment 2
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 6J
----------------------------------------------------------------------------------------------------
monitor.py
    Implements a simple monitor application that will detect password-guessing attempts
    against a service and block that IP using Netfilter.
    Monitors the /var/log/secure file.
    User specifies max attempts and blocking duration for the iptables rules to block.
----------------------------------------------------------------------------------------------------
"""
import sys
import time
import os
import re
import subprocess
import threading

SECURE_LOG_PATH = "/var/log/secure"
global max_attempts
global block_duration
hostnames = {}


def read_user_input():
    """
    Display simple command line UI to read user input:
        max_attempts: Enter max password attempts before blocking IP.
        block_duration: Enter duration in seconds for blocking IP (Enter 0 for indefinite)
    :return: none
    """
    if not os.getuid() == 0:
        print("You must be root to change IPTables.")
        sys.exit(2)

    try:
        global max_attempts
        global block_duration

        while True:
            user_input = input("Enter max password attempts before blocking IP:")
            if user_input.isdigit():
                try:
                    max_attempts = int(user_input)
                    if max_attempts > 0:
                        break
                except ValueError:
                    print("Invalid input, not an integer.")
            print("Max attempts must be an integer greater than 0, please re-enter.")

        while True:
            user_input = input("Enter duration in seconds for blocking IP (Enter 0 for indefinite):")
            if user_input.isdigit():
                try:
                    block_duration = int(user_input)
                    if block_duration >= 0:
                        break
                except ValueError:
                    print("Invalid input, not an integer.")
            print("Block duration must an integer greater than or equal to 0, please re-enter.")

        # Start monitor function.
        # daemon=True so thread doesn't prevent program from exiting.
        t1 = threading.Thread(target=monitor_secure_log, daemon=True)
        t1.start()
        print("Press enter at any moment to quit.")
        user_input = input()
        sys.exit()

    except OSError as msg:
        print('Error Code : ' + msg.strerror)
        sys.exit()


def monitor_secure_log():
    """
    Tails /var/log/secure and monitors each new line for password-guessing attempt.
    If password-guessing detected parse IP address and call blocking handler.
    :return: None
    """
    f = subprocess.Popen(['tail', '-n0', '-f', SECURE_LOG_PATH], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    for line_b in f.stdout:
        line = line_b.decode("utf-8")
        if 'Failed password for' in line:
            print(line)
            ip_address_matches = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)

            if len(ip_address_matches) < 1:
                print("No IP address found in password attempt line in log.")
            elif len(ip_address_matches) > 1:
                print("More than 1 IP addresses found in password attempt line in log.")
            else:
                ip_address = ip_address_matches[0]
                handle_failed_password_attempt(ip_address)


def handle_failed_password_attempt(hostname):
    """
    Records total failed login attempts for IP address.
    If attempts exceeds user defined max attempts, block the IP for user specified block duration.
    :param hostname: IP address to block
    :return: None
    """
    global max_attempts
    if hostname not in hostnames:
        hostnames[hostname] = 0

    # Increment IP failed attempts
    attempts = hostnames[hostname] + 1
    hostnames[hostname] = attempts

    # Block IP if attempts greater or equal max attempts
    if attempts >= max_attempts:
        iptables_block_rule(hostname)


def iptables_block_rule(ip_address):
    """
    Adds iptables rule to block the specified IP address.
    Records timestamps of blocking start and end time.
    Starts a timer to unblock the iptables rule to user specifed block duration.
    :param ip_address: ip address to block
    :return: None
    """
    global block_duration

    ipcmd = f'/sbin/iptables -A INPUT -s {ip_address} -j DROP'
    subprocess.run(ipcmd, shell=True)

    if block_duration > 0:
        print(f'Blocking IP: {ip_address} for {block_duration} seconds.')
        rmv_ipcmd = f'/sbin/iptables -D INPUT -s {ip_address} -j DROP'
        start_time = time.perf_counter()
        print(f'Blocking IP: {ip_address} Start time: {start_time}')
        timer = threading.Timer(block_duration, iptables_unblock_rule, (rmv_ipcmd, ip_address, start_time))
        timer.start()
    elif block_duration == 0:
        print(f'Blocking IP: {ip_address} indefinitely.')


def iptables_unblock_rule(ipcmd, ip_address, start_time):
    """
    Drops iptables rule for to unblock an IP address.
    :param ipcmd: the iptables rule to run
    :param ip_address: the ip address to unblock
    :param start_time: the start timestamp
    :return: None
    """
    subprocess.run(ipcmd, shell=True)
    end_time = time.perf_counter()
    print(f'Unblocking IP: {ip_address} End time: {end_time}')
    print(f'Thread Time IP: {ip_address} Total time: {end_time - start_time}')


if __name__ == "__main__":
    read_user_input()
