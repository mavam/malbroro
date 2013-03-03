malBroro
========

The **mal**ware **Bro** **ro**asts repository contains a collection of
[Bro](http://www.bro-ids.org) scripts for detecting malware.

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

Untested
--------

This list of scripts represents experimental scripts for which I could not
yet obtain a sample trace.

- [cve-2013-1493.bro](cve-2013-1493.bro): detects McRAT C&C traffic by looking
  for a HTTP POST request to `/59788582` with the header `Content-Length: 44`,
  `Pragma: no-cache`, and `Host: 110.[0-9]+.55.187`.
