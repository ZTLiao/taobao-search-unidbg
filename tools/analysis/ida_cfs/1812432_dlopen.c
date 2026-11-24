// func dlopen @ 0x1ba7d0
// imports: dlopen@@LIBC

// attributes: thunk
void *dlopen(const char *file, int mode)
{
  return off_1C13A8(file, mode);
}
