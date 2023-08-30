## Power-Process

This a fork of the std library Command for Process creation in Windows (under same MIT/Apache2 licenses) to enable a few key use cases. Most files are straight from Rust std library modified to work outside the library. 

The reason for this is to have a more robust command experience and provide the customization of creating a Windows process that the std library is missing. This provides a way to get access to features now while they stabilize upstream but adheres to the Command API so it can be swapped to the std library.  The long term goal would be upstream many of the features here.

Some challenges this solves:

- Creating a process with in a Job Object
- Create a process with the command name different than the executable
- Don't inherit STDIO
- Create suspended processes and resume threads

