#include <stdlib.h>

int main(int argc, const char* argv[]) {
  
  float n = 1024000000; float a = 2.0f; float b = 3.0f;
  float *x = (float*) malloc(n * sizeof(float));
  float *y = (float*) malloc(n * sizeof(float));
  // Initialize x, y
  
  // Run SAXPY TWICE
#pragma omp target data map(to:x)
  {
    
#pragma omp target map(tofrom:y)
#pragma omp parallel for
      for (int i = 0; i < n; ++i){
	y[i] = a*x[i] + y[i];
      }
      
#pragma omp target map(tofrom:y)
#pragma omp parallel for
      for (int i = 0; i < n; ++i){
	y[i] = b*x[i] + y[i];
      }
  }
  
  free(x);
  free(y);

  return 0;
  
}
