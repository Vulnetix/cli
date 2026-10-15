var myHeaders = new Headers();
myHeaders.append("Content-Type", "application/json");
~>// myHeaders.append("Cookie", "csrftoken=Q8wd2LkS0pXz71nB; jwt=@@sample:a[G]Vh[Z]GV[y][.]c[G]F5[b]G9[h]ZA[.]c2[l]n3[k]2@@");
fetch("/api/lab", { method: "POST", headers: myHeaders });
