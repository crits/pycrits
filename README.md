pycrits
=======

Python interface to the CRITs API.

This is currently very minimal. It only supports GETs.

Here's some basic usage:

```
from pycrits import pycrits

crits = pycrits('http://localhost:8000', 'wxs', '<api_key>')
for batch in crits.indicators():
    print len(batch['objects'])
```
