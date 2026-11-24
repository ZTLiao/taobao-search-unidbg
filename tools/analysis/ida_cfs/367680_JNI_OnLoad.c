// func JNI_OnLoad @ 0x59c40
// imports: EXPORT:JNI_OnLoad

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
  _ReadStatusReg(TPIDR_EL0);
  JUMPOUT(0x59CA8);
}
