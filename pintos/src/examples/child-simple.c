/* Child process run by exec-multiple, exec-one, wait-simple, and
   wait-twice tests.
   Just prints a single message and terminates. */

#include <stdio.h>

const char *test_name = "child-simple";

int
main (void) 
{
  printf("blah blah");
  return 81;
}
