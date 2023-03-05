# BaseAddressDiscoverererer
A python3 script for generating a list of possible base addresses given a raw binary program

This program works by looking for 32-bit words with the least two significant bytes being null.  This list becomes the candidate list.  The script then checks if any other double words have the same two most significant bytes as the candidate list and outputs the top 5 highest matches.

Example:

```
$ python DiscoverBaseAddress.py u-boot.bin big
Top 5 results
('e1a00000', {'count': 2599})
('e59f0000', {'count': 1818})
('e3a00000', {'count': 1804})
('49fb0000', {'count': 1372})
('ea000000', {'count': 889})
```

You can then try disassembly with these double words as base addresses.
In the example above, `49fb0000` was the correct base load address.