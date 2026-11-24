// func open @ 0x1ba850
// imports: open@@LIBC

// attributes: thunk
int open(const char *file, int oflag, ...)
{
  return off_1C13E8(file, oflag);
}
