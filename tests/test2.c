#include <stdio.h>

typedef enum e_machin
{
  TITI,
  TOTO,
  TATA
} machin;

typedef struct s_truc
{
  int foo;
  double bar;
} truc;

static int svar;

int gvar = 42;

static int sfun(void)
{
  puts("sfun");

  return 42;
}

int main(void)
{
  machin m = TOTO;
  truc s = { 0 };
  int i = 0;

  puts("main");
  printf("%d %d\n", m, s.foo);
  sfun();

  return i;
}
