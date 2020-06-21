void insertionSort( int* v, int n )
{
  int i   = 0;
  int j   = 1;
  int aux = 0;
  
  while (j < n)
  {
    aux = v[j];
    i   = j - 1;
    while ((i >= 0) && (v[i] > aux))
    {
      v[i + 1] = v[i];
      i = i - 1;
    }
    v[i + 1] = aux;
    j = j + 1;
  }
}