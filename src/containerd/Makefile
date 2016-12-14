PREFIX ?= /usr/local
PYTHON ?= python

fetch:
	fetch --no-verify-peer https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso \
	-o ${WRKSRC}/virtio-win.iso

install:
	install etc/containerd ${PREFIX}/etc/rc.d/
	install sbin/containerd ${PREFIX}/sbin/
	install -d ${PREFIX}/lib/containerd
	install -d ${PREFIX}/lib/containerd/src
	install -d ${PREFIX}/lib/containerd/plugins
	install -d ${PREFIX}/share/containerd
	cp -a src/ ${PREFIX}/lib/containerd/src/
	cp ${WRKSRC}/virtio-win.iso ${PREFIX}/share/containerd
