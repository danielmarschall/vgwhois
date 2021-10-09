# VGWhoIs - ViaThinkSoft Global WhoIs

VGWhoIs is a fork of the tool GWhoIs. It allows users to find information about domains, IP addresses,
ASN numbers etc by querying the best fitting WhoIs service automatically. The information about the
whois services is stored in a pattern file and can be altered or extended by new pattern files.

The pattern files which contain the whois servers of all existing top-level-domains is actively maintained and updated
regularly!

In regards querying OID information, VGWhoIs supports The [OID-Information-Protocol](https://datatracker.ietf.org/doc/draft-viathinksoft-oidip/).

## Usage

The usage is pretty simple:

    vgwhois example.com

## Installation

On Linux, copy all files into a directory of your choice and run `install.sh` as root.
To uninstall, run `uninstall.sh`.

The installation scripts create symbolic links on your file system,
therefore, the program files need to stay at the chosen location after installing.

