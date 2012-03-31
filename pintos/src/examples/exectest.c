#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  wait (exec ("child-simple"));
}
