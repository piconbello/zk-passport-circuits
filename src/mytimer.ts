export async function mytime<T = any>(msg: string, func: ()=>Promise<T>): Promise<T> {
  console.time(msg);
  const res = await func();
  console.timeEnd(msg);
  return res;
}