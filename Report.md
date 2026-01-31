### Результат

Мы видим что код ```<div class='message'>Invalid request: /<script>alert(Hjack)</script></div>``` попал без экарнирования так же как в браузере. Скриншоты так же приложенны из браузера.

### Что было сделано
- в изначальном коде были небольшие доработки из за портов 
- добавлено получение ответа от сервера responses = sniff
- обработка ответа в цикле по пакетам что бы собрать его
- для удобства переносы были заменены в ответе 
- добавлена отправка закрытие FIN




```
Sidelnikov@Note-SPB MINGW64 /d/Project/Python/HSE/HSE-DZ8 (main)
$ python dz8.py ignored '<script>alert('Hjack')</script>' 1
Begin emission
..
Finished sending 1 packets
.....*
Received 8 packets, got 1 answers, remaining 0 packets

=== Запрос #1 ===
Заголовки ответа:
HTTP/1.1 200 OK
cache-control: no-cache
content-type: text/html
pragma: no-cache
x-xss-protection: 0
x-cloud-trace-context: e289345ec8cf1d6f25a325ffdb3c6f80
date: Sat, 31 Jan 2026 17:10:10 GMT
server: Google Frontend
Content-Length: 2255
Connection: close

 Тело ответа:
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Error</title>
<style>
/* Copyright 2017 Google Inc. */

body, html, td, span, div, input, textarea {
  font-family: sans-serif;
  font-size: 14pt;
}

body {
  background: url('cheese.png') top center repeat;
  text-align: center;
  opacity: 0.80;
}

h2 {
  text-align: center;
  font-size: 30pt;
  font-weight: bold;
}

td {
  vertical-align: top;
  padding: 5px;
}

a, a:hover {
  text-decoration: underline;
  color: #0000bb;
}

a:visited {
  color: #bb0000;
}

a.button:visited {
  color: #0000bb;
}

.content {
  text-align: left;
  margin-left: auto;
  margin-right: auto;
  width: 90%;
  background: #ffffcc;
  padding: 20px;
  border: 3px solid #ffb149;
}

.menu {
  text-align: left;
  padding: 10px 20px 35px 20px;
  margin-left: auto;
  margin-right: auto;
  margin-top: 20px;
  width: 90%;
  background: #ffffcc;
  border: 3px solid #ffb149;
}

.menu-user {
  color: #000000;
  font-weight: bold;
}

#menu-left {
  float: left;
}

#menu-left a, #menu-left a:hover, #menu-left a:visited {
  color: #000000;
}

#menu-right {
  float: right;
}

#menu-right a, #menu-right a:hover, #menu-right a:visited {
  color: #000000;
}

.message {
  width: 50%;
  color: #ff0000;
  background: #ffdddd;
  border: 2px solid #ff0000;
  border-radius: 1em;
  -moz-border-radius: 1em;
  padding: 10px;
  font-weight: bold;
  text-align: center;
  margin: auto;
  margin-top: 20px;
  margin-bottom: 20px;
}

input, textarea {
  background-color: #ffffff;
}

.refresh {
  float: center;
  width: 90%;
  text-align: right;
  margin: auto;
  padding-top: 0;
  padding-bottom: 2pt;
  margin-top: 0;
  margin-bottom: 0;
}

.h2-with-refresh {
  margin-bottom: 0;
}

</style>

</head>

<body>

<div class='menu'>
  <span id='menu-left'>
    <a href='/606349775900031768833848789123437690829/'>Home</a>

  </span>
  <span id='menu-right'>


      <a href='/606349775900031768833848789123437690829/login'>Sign in</a>
      | <a href='/606349775900031768833848789123437690829/newaccount.gtl'>Sign up</a>

  </span>
</div>



<div class='message'>Invalid request: /<script>alert(Hjack)</script></div>


</body>

</html>


 Завершено 1 запросов

```

![Код в браузере](scr_code.jpg)
![Результат инекции](scr_res.jpg)