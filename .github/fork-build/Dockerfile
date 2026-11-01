# quay.io/samba.org/samba-server (what samba-operator runs share pods from) with streams_xattr.so
# from this branch. Not for upstream.
#
# A VFS module must come from the same build as the smbd that loads it, so it is built with
# Fedora's own spec for exactly the samba in the base image, with Source0 swapped for this branch
# (samba-4.24.7.tar.xz, from git archive in the workflow). Only streams_xattr.so goes into the
# image; the image stage refuses to build if the base image's samba isn't the one built here.
# Quay prunes samba-server digests once :latest moves on, so a rebuild may need a fresh pin.
ARG SAMBA_NVR=4.24.7-1.fc44

FROM fedora:44@sha256:43b29f65a41eb9c35e1cd5323e3bdf3b655c2357a9f4f1ff2f9c2798e5045d80 AS builder
ARG SAMBA_NVR

RUN dnf -y install rpm-build dnf5-plugins cpio && dnf clean all

# Koji keeps every build, unlike the updates repo, which only carries the newest.
ADD --checksum=sha256:fe360456681f0acbffa97d8419e2ca032a08133f7ad4ed1653ecaf2f243bf672 \
    https://kojipkgs.fedoraproject.org/packages/samba/4.24.7/1.fc44/src/samba-4.24.7-1.fc44.src.rpm /tmp/

RUN rpm -i /tmp/samba-${SAMBA_NVR}.src.rpm \
 && dnf -y builddep /root/rpmbuild/SPECS/samba.spec \
 && dnf clean all

# Source0 is now this branch, not the signed release tarball, so drop the signature check. Tests
# and debuginfo are skipped; everything else is built as Fedora builds it.
COPY samba-4.24.7.tar.xz /root/rpmbuild/SOURCES/
RUN cd /root/rpmbuild \
 && sed -i '/%{gpgverify}/d' SPECS/samba.spec \
 && rpmbuild -bb --nocheck --define 'debug_package %{nil}' SPECS/samba.spec \
 && mkdir /out && cd /out \
 && rpm2cpio /root/rpmbuild/RPMS/$(uname -m)/samba-${SAMBA_NVR}.$(uname -m).rpm \
    | cpio -idm --quiet ./usr/lib64/samba/vfs/streams_xattr.so

FROM quay.io/samba.org/samba-server@sha256:c4f35a1a420fab74c2dc319b4b30106b2b27fc4ea7bf953af4185ef4e0718f6f AS image
ARG SAMBA_NVR

RUN v=$(rpm -q --qf '%{VERSION}-%{RELEASE}' samba) \
 && [ "$v" = "$SAMBA_NVR" ] || { echo "base image has samba $v, module is built for $SAMBA_NVR"; exit 1; }

COPY --from=builder /out/usr/lib64/samba/vfs/streams_xattr.so /usr/lib64/samba/vfs/streams_xattr.so

# Runs smbd with the cluster's share options and checks what lands on disk. Not part of the
# image: the workflow builds this target before pushing anything.
FROM image AS test
COPY test.py /test/test.py
RUN python3 -I /test/test.py

FROM image
