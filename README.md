This repository contains [Bro](http://www.bro-ids.org) scripts for detecting
malware.

Usage
=====

Clone this script into your `site` directory and add

    @load ./malbroro

to your `local.bro`.

Malware
=======

- [Miniduke](miniduke.bro): detects Miniduke C&C traffic by looking for a HTTP
  body with MIME type `image/gif` in reponse to a request with URIs like
  `.*index.php?e=Rqut1NbyoQkT`.
