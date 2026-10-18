"""Runs smbd from the image with the cluster's share options and checks the bytes streams_xattr
leaves on disk, so a module that doesn't load, or stores the wrong format, never gets pushed.

[compat] is how the cluster's shares are set up (xattr_compat = yes): streams are plain user.*
xattrs, shared with NFS named attributes. [stock] is the same with Samba's default format, stream
data plus a trailing 0 byte. [refused] combines xattr_compat = yes with extents, which smbd must
refuse to connect.
"""

import os
import socket
import subprocess
import sys
import time

T = "/tmp/t"
CONF = f"{T}/smb.conf"
PASSWORD = "test"

SHARE = """\
	vfs objects = catia fruit streams_xattr
	fruit:encoding = native
	fruit:convert_adouble = no
	fruit:resource = stream
	fruit:metadata = netatalk
	fruit:zero_file_id = no
	ea support = no
	streams_xattr:prefix = user.
	streams_xattr:store_stream_type = no
"""

failures = []


def check(what, got, expected):
    if got == expected:
        print(f"ok: {what}")
    else:
        print(f"FAIL: {what}: got {got!r}, expected {expected!r}")
        failures.append(what)


def smbclient(share, commands):
    return subprocess.run(
        ["smbclient", f"//127.0.0.1/{share}", "-s", CONF, "-U", f"root%{PASSWORD}",
         "-m", "SMB3", "-c", commands],
        capture_output=True, text=True)


def streams(share, name):
    """allinfo's stream lines, as {name: size}."""
    out = smbclient(share, f"allinfo {name}").stdout
    result = {}
    for line in out.splitlines():
        # stream: [:smb:$DATA], 5 bytes
        if line.startswith("stream: [") and not line.startswith("stream: [::$DATA]"):
            stream, size = line[len("stream: ["):].split("], ")
            result[stream] = int(size.split()[0])
    return result


def setup():
    for d in (T, f"{T}/private", f"{T}/lock", f"{T}/state", f"{T}/cache", f"{T}/run",
              "/srv/compat", "/srv/stock"):
        os.makedirs(d, exist_ok=True)
    with open(CONF, "w") as f:
        f.write(f"""\
[global]
	server role = standalone server
	interfaces = lo
	bind interfaces only = yes
	smb ports = 445
	disable netbios = yes
	load printers = no
	printcap name = /dev/null
	disable spoolss = yes
	passdb backend = tdbsam:{T}/private/passdb.tdb
	private dir = {T}/private
	lock directory = {T}/lock
	state directory = {T}/state
	cache directory = {T}/cache
	pid directory = {T}/run
	ncalrpc dir = {T}/run/ncalrpc
	log file = {T}/log.%m
	log level = 2

[compat]
	path = /srv/compat
	read only = no
{SHARE}	streams_xattr:xattr_compat = yes

[stock]
	path = /srv/stock
	read only = no
{SHARE}
[refused]
	path = /srv/compat
{SHARE}	streams_xattr:xattr_compat = yes
	streams_xattr:max xattrs per stream = 2
""")
    subprocess.run(["smbpasswd", "-c", CONF, "-a", "-s", "root"],
                   input=f"{PASSWORD}\n{PASSWORD}\n", text=True, check=True)
    for name, data in (("world", b"world"), ("hi", b"hi"), ("empty", b"")):
        with open(f"{T}/{name}", "wb") as f:
            f.write(data)
    subprocess.run(["smbd", "-s", CONF, "-D"], check=True)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", 445), timeout=1).close()
            return
        except OSError:
            time.sleep(0.1)
    sys.exit("smbd did not start")


def test_compat():
    f = "/srv/compat/file"
    open(f, "wb").close()
    os.setxattr(f, "user.foreign", b"hello")

    r = smbclient("compat", f"get file:foreign {T}/out; put {T}/world file:smb; "
                            f"put {T}/empty file:empty")
    check("compat: smbclient", r.returncode, 0)
    with open(f"{T}/out", "rb") as out:
        check("compat: foreign xattr read as stream", out.read(), b"hello")
    check("compat: stream stored without trailing byte", os.getxattr(f, "user.smb"), b"world")
    check("compat: empty stream is a zero-length xattr", os.getxattr(f, "user.empty"), b"")

    smbclient("compat", f"put {T}/hi file:smb")
    check("compat: overwrite truncates", os.getxattr(f, "user.smb"), b"hi")

    check("compat: stream list", streams("compat", "file"),
          {":foreign:$DATA": 5, ":smb:$DATA": 2, ":empty:$DATA": 0})


def test_stock():
    f = "/srv/stock/file"
    open(f, "wb").close()

    r = smbclient("stock", f"put {T}/world file:smb; get file:smb {T}/out")
    check("stock: smbclient", r.returncode, 0)
    check("stock: stream stored with trailing byte", os.getxattr(f, "user.smb"), b"world\0")
    with open(f"{T}/out", "rb") as out:
        check("stock: stream read back", out.read(), b"world")
    check("stock: stream list", streams("stock", "file"), {":smb:$DATA": 5})


def test_refused():
    r = smbclient("refused", "ls")
    check("refused: tree connect fails", r.returncode != 0, True)


setup()
try:
    test_compat()
    test_stock()
    test_refused()
finally:
    with open(f"{T}/run/smbd.pid") as pid:
        os.kill(int(pid.read()), 15)

if failures:
    for log in sorted(os.listdir(T)):
        if log.startswith("log."):
            print(f"===== {log}")
            with open(f"{T}/{log}") as f:
                print(f.read()[-4000:])
    sys.exit(f"{len(failures)} check(s) failed")
