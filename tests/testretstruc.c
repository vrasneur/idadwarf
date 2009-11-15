#include <stdio.h>

typedef struct
{
  int a;
  char *b;
} foo;

foo f(int a, char *b)
{
  return (foo){ .a = a, .b = b };
}

int main(void)
{
  foo bar = f(1, "truc");

  printf("a: %d, b: '%s'\n", bar.a, bar.b);

  return 0;
}
