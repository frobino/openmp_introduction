/*

  This program will numerically compute the integral of

  4/(1+x*x) 
				  
  from 0 to 1.  The value of this integral is pi -- which 
  is great since it gives us an easy way to check the answer.

  The is the original sequential program.  It uses the timer
  from the OpenMP runtime library

  History: Written by Tim Mattson, 11/99.

*/

#include <stdio.h>
#include <time.h>

static long num_steps = 1000000000;
double step;

void main ()
{
  int i;
  double x, pi, sum = 0.0;
  // Alloc variables to get execution time
  double run_time;
  clock_t start_time, end_time;

  step = 1.0/(double) num_steps;

  start_time = clock();

  for (i=0;i<= num_steps; i++){
    x = (i-0.5)*step;
    sum = sum + 4.0/(1.0+x*x);
  }

  pi = step * sum;

  end_time = clock();

  run_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
  printf("\n pi with %d steps is %f in %f seconds\n",num_steps,pi,run_time);
  
}
