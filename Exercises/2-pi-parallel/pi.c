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

// HP max nr cores. Otherwise I will have to allocate psum dinamically
#define MAX_N_CORES 48

static long num_steps = 1000000000;
double step;

void main ()
{
  int i;
  double x, pi, sum = 0.0;
  // Alloc variables to get execution time
  double start_time, run_time;

  // Alloc variables needed to share job btw threads/tasks
  int n_threads;
  double psum[MAX_N_CORES];

  step = 1.0/(double) num_steps;

  // Start measuring time
  start_time = omp_get_wtime();

#pragma omp parallel num_threads(2)
  {

    n_threads = omp_get_num_threads();
    int myid = omp_get_thread_num();
    int i; //private for each thread
    double x; //private for each thread
    psum[myid] = 0;

    int mystart,myend;
    mystart=num_steps*myid/n_threads;
    myend = num_steps*(myid+1)/n_threads;

    for (i = mystart;i <= myend; i++){
      x = (i-0.5)*step;
      psum[myid] = psum[myid] + 4.0/(1.0+x*x);
    }

  }

  for (i=0;i<n_threads;i++)
    sum +=psum[i];

  pi = step * sum;

  run_time = omp_get_wtime() - start_time;

  printf("\n pi with %d steps is %f in %f seconds\n",num_steps,pi,run_time);
  
}
