A simple script to convert between the format that PuTTY stores its known hosts public SSH keys in (in the windows registry)
and the format that openssh stores them in (in the known_hosts file).

options are explained by running `python3 openssh_putty_knownhost_converter --help`

This requires windows because of the requirement to use the `winreg` module to access the registry. If necessary i can make it read in a .reg file but I only needed this on windows, so...

This is based off of https://bitbucket.org/kobowi/reg2kh/ , but fixed up because the way his code explains what it is doing is completely wrong. For a proper explaination on what is going on see http://stackoverflow.com/a/13104466/975046

This is written in python 3 and doesn't use any external libraries.