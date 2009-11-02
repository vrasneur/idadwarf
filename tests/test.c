#include <stdio.h>

int g(int a, int b)
{
  int c = (a + b + 1) / 2;

  return c;
}

int f(int a, int b)
{
  int c = a * 2;

  c += b;

  return c;
}

int main(void)
{
  int a = f(1, 2);

  printf("res: %d\n", g(a, 1));
}
