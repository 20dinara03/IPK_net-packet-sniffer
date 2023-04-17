# ChangeLog
## 0.0.1 - 2023-04-14 
>When I started parsing input arguments, I ran into the problem that I needed the filter flags (true or false) to be available from any part of the program.
But I quickly solved this problem by creating a structure that stores all the information about the input arguments
### Added
Initial stage: parsing input arguments
## 0.1.0 - 2023-04-15 
>Then I ran into the problem that when parsing arguments, I compared not only the flags, but also the names of the interfaces and the like. Because of this, errors about an unknown argument were displayed. This problem was also solved very easily, I just skipped one argument where necessary
### Added
Adding flag argument jumping where appropriate
## 0.2.0 - 2023-04-15 
>I also realized that it is necessary to start parsing not from argument 0, but from the first. And rewrite exit() to return, because main is int type program.
### Added
* Start parsing from 1
* Rewrite exit() to return
## 0.5.0 - 2023-04-15
>The hardest bug to fix turned out to be IPv upper-layer protocol and not supported by proto[x] . I still do not understand what the problem is, perhaps in the old version of the compiler. But I had to completely reinstall gcc
### Fixed
Fix ndp and mld flags in filter
## 1.0.0 - 2023-04-17
>The last thing I ran into was a Segmentation fault when no flag other than -i is set. This was fixed by checking for all flags to false and fixing everything to true in this case
### Fixed
Array size fixes to avoid Segmentation fault
