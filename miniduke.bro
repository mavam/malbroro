##! Detects Miniduke C&C traffic by looking for a GIF in reponse to an HTTP
##! request for an index.php with obfuscated parameter.
@load base/frameworks/notice

module Malware;

export {
  redef enum Notice::Type += {
    ## Miniduke C&C activity.
    Miniduke_CC_Activity
  };
}

redef record HTTP::Info += {
  miniduke: string &optional;
};

function report(c: connection, uri: string)
  {
    local param = split1(uri, /=/)[2];
    local payload = decode_base64(gsub(gsub(param, /-/, "+"), /_/, "/"));
    NOTICE([$note=Miniduke_CC_Activity,
           $msg=fmt("Miniduke C&C activity: %s", payload),
           $conn=c]);
  }

event http_request(c: connection, method: string, original_URI: string,
    unescaped_URI: string, version: string)
  {
    if ( /index\.php\?[[:alnum:]]+=([=-_]|[[:alnum:]])+/ in unescaped_URI )
      c$http$miniduke = unescaped_URI;
  }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
  {
    if ( is_orig || ! c$http?$miniduke || /image\/gif/ !in c$http$mime_type )
      return;
    report(c, c$http$miniduke);
    delete c$http$miniduke;
  }

# This one works as well and fires a bit earlier, but using c$http$mime_type
# is more robust detection scheme since the server could "lie" to use with the
# Content-Type header.
#
#event http_header(c: connection, is_orig: bool, name: string, value: string)
#  {
#    if ( is_orig || ! c$http?$miniduke || name != "CONTENT-TYPE" )
#      return;
#
#    if ( /application\/octet-stream/ in value )
#      report(c$id$resp_h, c$http$miniduke);
#
#    delete c$http$miniduke;
#  }
