#!/usr/bin/env python3
"""Broker-only launch barrier and permanent privilege drop; no approval logic."""
import os
import pwd
import sys


def main():
    if os.geteuid() != 0:
        raise PermissionError("executor trampoline requires broker root")
    uid = int(sys.argv[1])
    if uid <= 0:
        raise PermissionError("root executor forbidden")
    account = pwd.getpwuid(uid)
    if os.read(0, 1) != b"G":
        raise PermissionError("broker launch barrier closed")
    # Do not inherit root's supplementary groups or saved IDs.
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(uid)
    if os.getuid() != uid or os.geteuid() != uid:
        raise PermissionError("privilege drop failed")
    os.chdir(sys.argv[2])
    os.umask(0o077)
    with open(os.devnull, "rb") as stream:
        os.dup2(stream.fileno(), 0)
    os.execve(sys.argv[3], sys.argv[3:], os.environ)


if __name__ == "__main__":
    main()
