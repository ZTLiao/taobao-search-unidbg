// func fopen @ 0x1bab60
// imports: fopen@@LIBC

// attributes: thunk
FILE *fopen(const char *filename, const char *modes)
{
  return off_1C1570(filename, modes);
}
