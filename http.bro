##! Provides basic functionality for HTTP-based malware.

redef record HTTP::Info += {
  ## An opaque string to track malware activity through an HTTP session.
  malware: string &optional;
};

