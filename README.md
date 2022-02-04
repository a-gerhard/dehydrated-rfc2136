# dehydrated hook for dns-01 challenges via RFC 2136

This is a hook for the dehydrated acme client that lets you propagate your dns-01 challenge tokens via RFC 2136.

## Setup

First, install python3 as well as the `pyyaml` and `dnspython` packages via pip (or system packages)

Copy `dns01_hook.py` into /var/lib/dehydrated/hooks/

Set up dehydrated to use this hook:
```
HOOK="${BASEDIR}/hooks/dns01_hook.py"
CHALLENGETYPE="dns-01"
```

copy the example config (`dns01.yml`) to /etc/dehydrated/dns01.yml and configure the challenge for each domain you'll need to verify via dns-01 challenge. For more information, consult the comments in this file
