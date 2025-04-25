#include <Windows.h>

void reverse_bytes(const PBYTE data, const DWORD len) {
  for (DWORD i = 0; i < len / 2; i++) {
    const BYTE tmp = data[i];
    data[i] = data[len - 1 - i];
    data[len - 1 - i] = tmp;
  }
}
