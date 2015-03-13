
This is my collection of random wireshark dissectors that I've spent any significant time writing. They are all written in Lua, which is the bane of my existence. I hope you enjoy using them.

Currently contains:

1) Teamviewer dissector

2) Oracle SQL*Net / Net8 dissector

3) [MC-NMF](http://msdn.microsoft.com/en-us/library/cc219293.aspx), including contained [MC-NBFSE](http://msdn.microsoft.com/en-us/library/cc219190.aspx)
Note, this is currently linked to two TCP ports that were useful to me. Most likely, you will need to change those or manually "Decode As" NMF to make use of this dissector, since I do not believe there is a "default" port for NMF

More to come... 


# Code license

* [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)
