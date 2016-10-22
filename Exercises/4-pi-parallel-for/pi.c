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
#include <omp.h>

static long num_steps = 1000000000;
double step;

void main ()
{
  int i;
  double x, pi, sum = 0.0;
  // Alloc variables to get execution time
  double start_time, run_time;

  step = 1.0/(double) num_steps;

  // Start measuring time
  start_time = omp_get_wtime();

#pragma omp parallel num_threads(2)
  {
    double x; // private
    double sum = 0.0; // private
    
    #pragma omp for
    for (i=0;i<= num_steps; i++){
      x = (i-0.5)*step;
      sum = sum + 4.0/(1.0+x*x);
    }
    
    # pragma omp critical
    pi += step * sum;
  }
  
  run_time = omp_get_wtime() - start_time;
  printf("\n pi with %d steps is %f in %f seconds\n",num_steps,pi,run_time);
  
}
