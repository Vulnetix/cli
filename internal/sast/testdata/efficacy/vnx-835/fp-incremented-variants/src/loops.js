function scan(arr, n) {
  let i = 0;
  while (i < n) {
    for (; i < n && arr[i] !== 0; i++) {}
    i += 2;
  }
}
