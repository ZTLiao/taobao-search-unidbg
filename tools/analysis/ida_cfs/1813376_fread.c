// func fread @ 0x1bab80
// imports: fread@@LIBC

// attributes: thunk
size_t fread(void *ptr, size_t size, size_t n, FILE *stream)
{
  return off_1C1580(ptr, size, n, stream);
}
