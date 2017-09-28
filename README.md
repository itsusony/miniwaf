# miniwaf_perl

perl version of miniwaf

This tool can scan nginx error_log, parse illegal client_ip, add ip into deny.conf,  
and you nginx must include deny.conf, tool will reload nginx for you when new ips are appended.
`/usr/local/nginx/sbin/nginx -s reload`

```
        location / {
            include deny.conf;
            root   /var/www/site;
            index  index.html index.htm index.php;
        }
```

I used `File::Tail` to listen the changes of error log file.
this function is not in C version.

https://github.com/itsusony/miniwaf_perl/blob/master/miniwaf.pl#L4

# other
if you need performance, you can use this C version.
https://github.com/itsusony/miniwaf
