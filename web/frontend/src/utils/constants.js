export const DEFAULT_CODE = `#include <stdlib.h>
int main() {
  int* p = (int*)malloc(64);
  return 0;
}`;

export const editorOptions = {
  minimap: { enabled: false },
  fontSize: 16,
  automaticLayout: true,
  padding: { top: 20, bottom: 20 },
  scrollBeyondLastLine: false,
};

export const analyzeStats = [
  ['Allocations', 'total_allocations'],
  ['Frees', 'total_frees'],
  ['Leaks', 'total_leaks', true],
  ['Bytes', 'total_bytes_allocated'],
];
