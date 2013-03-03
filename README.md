malBroro
========

The **malBroro** (**mal**ware **Bro** **ro**asts) repository contains
a collection of [Bro](http://www.bro-ids.org) scripts for detecting malware.

Usage
=====

Quick Start
-----------

    git clone git://github.com/mavam/malbroro.git
    bro -C -r trace.pcap ./malbroro
    bro -i eth0 ./malbroro

Integration
-----------

Clone this script into your `site` directory and add

    @load ./malbroro

to your `local.bro`.

Malware
=======

Tested
------

This list of scripts has received unit-testing with a PCAP trace of the
exploit.

- [miniduke.bro](miniduke.bro): detects [Miniduke](http://t.co/9r7olW2mz4) C&C
  traffic by looking for a HTTP body with MIME type `image/gif` in reponse to a
  request with URIs like `.*index.php?e=Rqut1NbyoQkT`.
