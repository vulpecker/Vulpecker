# VulPecker: An Automated Vulnerability Detection System Based on Code Similarity Analysis

Vulnerability Patch Database (VPD) contains mappings between CVE-IDs and diffs. 
A unified diff consists of a sequence of diff hunks. Each hunk contains the changed filename, and a sequence of additions and deletions. Added source code lines are prefixed by a “+” symbol, and deletions are prefixed by a “-”symbol.

Vulnerability Code Instance Database (VCID) contains many function groups with same vulnerabilities and involves all kinds of code reuse types.

VPD contains 19 C/C++ open-source software (Linux kernel, Firefox, Thunderbird, Seamonkey, Fixfox esr, Thunderbird esr, Wireshark, Ffmpeg, Apache Http Server, Xen, OpenSSL, Qemu, Libav, Asterisk, Cups, Freetype, Gnutls, Libvirt, VLC media player) with 1,761 vulnerabilities that involve 3,454 diff hunks, and VCID contains 455 unpatched function instances.
