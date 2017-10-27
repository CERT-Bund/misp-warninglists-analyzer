# MISP-Warninglists Analyzer
## Description
Checks observable against the MISP-warninglists.

## Requirements
To be able to install pygit2, libgit2-devel (libgit2.h) has to be installed. See requirements.txt for python dependencies.

## Configuration
```
MISPWarningLists {
  enablepull = true # allow cloning (later pulling) the repo (default: true)
  alloweddelta = 86400 # time in seconds, when updating is necessary (default: 86400s (24h))
}
```