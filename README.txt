#+TITLE: README for fasguard-benign-traffic-collection

* Introduction

fasguard-benign-traffic-collection is a tool designed to capture,
classify, and save network traffic to be used as a training set for
the FASGuard automatic IDS rule generation tool.

* Packet Classification

To improve the quality of the generated IDS rules, FASGuard wants the
training packets sorted by service.

fasguard-benign-traffic-collection assumes that the packets can be
adequately sorted by simply looking at the UDP/TCP port numbers and
trusting that the lesser of the two port numbers indicates the
service.  This is true for most Internet traffic.  For example,
clients connecting to an HTTP service will initiate a TCP connection
to destination port 80 with a source port higher than 1024 because
lower ports are usually reserved by the operating system.

A higher-quality sorting job requires stateful session and fragment
tracking.  Unfortunately, state tracking requires complex code; it
doesn't work when packets are load balanced, asymmetrically routed, or
randomly sampled (e.g., using sFlow); and the resources required to
process many concurrent sessions on a busy trunk link would probably
be too high.

** Details

Classification is done as follows:

  1. When a packet arrives, its ethertype is extracted.  Non-SNAP
     802.2 frames don't have an ethertype, so 0 is used.  Zero is
     an invalid ethertype, so there is no risk of collision.
  2. If the ethertype indicates that the packet is an IPv4 or IPv6
     packet, the protocol number is extracted.
  3. If the IP protocol number indicates that the packet is a TCP or
     UDP packet, the two port numbers are extracted and the lesser of
     the two is chosen.  If there is an error extracting the port
     numbers due to fragmentation, -1 is used.

The above algorithm yields one of the following service description
tuples:

  * (ethertype,)  # for non-IP packets
  * (ethertype, IP_protocol_number)  # for non-TCP/UDP IP packets
  * (ethertype, IP_protocol_number, port_number)  # for TCP/UDP packets

The packet's service description tuple and the settings in the
configuration file determine (a) whether the packet is kept or
discarded and (b) if kept, where to save the packet.

* Configuration

The configuration file syntax is a single Python dict literal.  Each
key is a string identifying a configuration setting that maps to a
setting-specific Python literal object (e.g., a list or another
dict).  For specifics, see config.py.

* emacs org-mode settings                                          :noexport:
  :PROPERTIES:
  :VISIBILITY: folded
  :END:
#+STARTUP: showall
#+OPTIONS: toc:nil ^:{} H:10
one inch margins on letter paper:
#+LATEX_HEADER: \usepackage[letterpaper,margin=1in,twoside]{geometry}%
get rid of the ugly red borders around clickable links:
#+LATEX_HEADER: \hypersetup{pdfborder={0 0 0}}
fix fonts
#+LATEX_HEADER: \usepackage{lmodern}

Local Variables:
mode:org
End:
