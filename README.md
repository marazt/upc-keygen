UpcKeyGen
==================

Version 1.0.0

Author marazt

Copyright marazt

License The MIT License (MIT)

Last updated 29 September 2016


About
-----------------

UpcKeyGen is a PowerShell script for generation passwords and connection to the UPC router. It internally uses C# code for password generation
inspired by [upckeys repository](https://github.com/martinsuchan/upckeys).


Abilities
-----------------
+ Generate passwords from UPC router SSID
+ Connection to the router with generated passwords


Versions
-----------------

**1.0.0 - 2015/09/29**

* Initial version


Example Configuration
-----------------
* Generate passwords: UpcKeyGen.ps1 -ssid UPC1234567
* Generate passwords and try to connect: UpcKeyGen.ps1 -ssid UPC1234567 -connect true

