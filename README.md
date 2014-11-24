pycrits
=======

Python interface to the CRITs API.

This is currently very minimal. It only supports GETs.

Here's some basic usage:

```
from pycrits import pycrits

crits = pycrits('http://localhost:8000', 'wxs', '<api_key>')
for batch in crits.indicators():
    print len(batch)
```

Here's an example of how to fetch a PCAP. If nothing is found you will
get an empty list back. These are all fetching the same file.

```
>>> from pycrits import pycrits
>>> crits = pycrits('http://localhost:8000', 'wxs', 'c7017158803056f823486adb58d7d67a0b344ce7')
>>> x = crits.fetch_pcap(md5='67cc75e608b4f37ed993bf84fafafb9d')
>>> print len(x[0]['data'])
22279
>>> x = crits.fetch_pcap(id_='51ac0abcd6fa25ca9d2d277f')
>>> print len(x[0]['data'])
22279
>>> x = crits.fetch_pcap(params={'c-filename': 'sedtest.pcap'})
>>> print len(x[0]['data'])
22279
>>>
```
