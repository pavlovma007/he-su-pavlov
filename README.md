# Тайные цифровые честные выборы , защищенные от мошенничества.  криптоалгоритм Хэ-Су (+моя модификация от вбросов)



В демократиях используются часто именно "тайные выборы". Но их не просто организовать без мошенничества. 

Допустим Вам  поручено организовать выборы, вы применили всю свою гениальность организатора но чисто организационными методами вам не решить задачу честных выборов. Даже если все пройдет гладко и никто из наблюдателей не сможет указать на недочёты, в вашей системе 100% будут слабые звенья, вероятны подкупы в любом месте... да многое вероятно. и то, что не доказано, что оно не случилось, еще не значит что оно не произошло на самом деле. Даже вы не можете быть уверены что все произошло так, как вы задумали - это люди и с ними всякое может случиться. 

Есть гипотеза, что организационными мерами не организовать честные тайные выборы, я считаю её доказанной.  И поиски решения привели меня к криптографическим и математическим методам. 

## Как работает это решение

Сразу покажу дамп запуска и потом будет описание 

```bash
$ /home/mp/MY/election/he-su-pavlov.py 
Registrator сформировал свои ключи
Registrator. отдал свой публичный ключ, кому-то, кто запросил
Elector. я сходил ножками в Регистратор и убедился, что способ моей авторизации у них согласован
для них я буду 2405601943451830377
Registrator. отдал свой публичный ключ, кому-то, кто запросил

Registrator. подписал для 2405601943451830377 число 802296053671535913931001997915925229955811890507558047990664467960904016194 , отправил ему подпись 764984103639585943648497847837578545294531918646118874999226835735641950478


Elector. регистратор подписал нам хеш публ ключа, не глядя. вычисленная из всех данных корректная подпись нашего публичного ключа=
 541864832565420547602553796598566062432634052362285312418132766570827450625
Agency. этап авторизации ключей избирателя
Agency. проверил подпись публичного ключа избирателя. её подписал действительно Регистратор
добавил её в список авторизованных
Agency. показал список авторизованных ключей

Elector. я завершил регистрацию своих новых ключей для голосования и авторизовал их еще до начала голосования, чтобы списки ключей тоже были фиксированы чтобы исключить вбросы
Registrator. Список избирателей (те, кто в принципе имеют право голосовать и им могут быть подписаны ключи)
[2405601943451830377]
Авторизованные ключи Публично (кто-то собирается с их помощью голосовать)
Agency. показал список авторизованных ключей
[{'public_key': b'\x80\x04\x95]\x00\x00\x00\x00\x00\x00\x00\x8c\tlib_bli'
                b'nd\x94\x8c\x03Key\x94\x93\x94\x8a ]\x8dr\xdc\\\x03L'
                b'\xe7\x1a\x7f\x12u\xb1\x8c\xbd5(1\x04;\x15\xe2\x86YK\xc8\xd7'
                b'\xe7\xbf\x828#\x8a \xa5*\xd8\xde\xcf3=[\xf1F\x83\x9a<'
                b'\x1f<\xef\x98\x8b\xf2\x9e\xdb\xfcH\x0e\xf9\xe93\x87)}T*\x86'
                b'\x94\x81\x94.',
  'public_key_sign': 541864832565420547602553796598566062432634052362285312418132766570827450625}]

!!! Теперь Началось Голосование !!!

Elector. создаём бюлетень, шифруем его новым, секретным ключём (aes пароль), и отправляем в агентство пачку шифров

Agency. проверил подпись Шифрованного бюлетня-ОК, проверил что этот публичный в списке авторизованных
добавил шифрованный бюлетень в список опубликованных шифрованных бюлетней :-P
у меня нет выбора : все ок и я не понимаю что в бюлетене, но судя по всему тот кто её прислал имеет право её прислать и я обязан её принять и опубликовать
Agency. выдал список опубликованных бюлетней
Agency. проверил избирателя - он авторизован, проверил подпись им секретного ключа его шифрованного бюлетеня - ок, публикую секретный пароль от его бюлетеня

проверка голосов! 
Публичная информация из которой ...
ЛЮБОЙ ЧУВЫРЛА может САМ посчитать результаты Тайных Цифровых выборов


шифрованные бюлетени
Agency. выдал список опубликованных бюлетней
[{'encripted_ballot': 61146089063342244480081076606,
  'encripted_ballot_sign': 10560785238957736231370584459517070084522693918724250307161555964439624760819,
  'mark_2': 5528835297277349927,
  'public_key': b'\x80\x04\x95]\x00\x00\x00\x00\x00\x00\x00\x8c\tlib_bli'
                b'nd\x94\x8c\x03Key\x94\x93\x94\x8a ]\x8dr\xdc\\\x03L'
                b'\xe7\x1a\x7f\x12u\xb1\x8c\xbd5(1\x04;\x15\xe2\x86YK\xc8\xd7'
                b'\xe7\xbf\x828#\x8a \xa5*\xd8\xde\xcf3=[\xf1F\x83\x9a<'
                b'\x1f<\xef\x98\x8b\xf2\x9e\xdb\xfcH\x0e\xf9\xe93\x87)}T*\x86'
                b'\x94\x81\x94.'}]

ключи от шифрованных бюлетеней
Agency. Отдаю список опубликованных паролей от бюлетеней
[{'mark_2': 5528835297277349927,
  'public_key': b'\x80\x04\x95]\x00\x00\x00\x00\x00\x00\x00\x8c\tlib_bli'
                b'nd\x94\x8c\x03Key\x94\x93\x94\x8a ]\x8dr\xdc\\\x03L'
                b'\xe7\x1a\x7f\x12u\xb1\x8c\xbd5(1\x04;\x15\xe2\x86YK\xc8\xd7'
                b'\xe7\xbf\x828#\x8a \xa5*\xd8\xde\xcf3=[\xf1F\x83\x9a<'
                b'\x1f<\xef\x98\x8b\xf2\x9e\xdb\xfcH\x0e\xf9\xe93\x87)}T*\x86'
                b'\x94\x81\x94.',
  'secret_keys': b'\x87$.a\xd1\x97g\xbd\xab2\xf8\x04 \xf4{%',
  'secret_keys_sign': 11139276119706190540316152842006857648254380536000602212675926756327950341529}]
Agency. показал список авторизованных ключей
Agency. выдал список опубликованных бюлетней
Agency. Отдаю список опубликованных паролей от бюлетеней

расшифруем бюлетень
найден ГОЛОС ЗА КАНДИДАТА: Candidate #2
```

Мне пришлось написать даже свою реализацию функций RSA, потому что поиск коммутативного blind алгоритма в готовых библиотеках не приводил к успеху (об этом поиске можно отдельно написать). 

Я давно , с 2022 решил что такое решение нужно, что власти , ЦИК и прочие структуры в разных странах , делая выборы электронными, ведут подсчёт по какому то алгоритму, не обозначая его наименование. А между тем учёные давно предлагают разные решения для честных криптографиских систем для  выборов и перечень разных алгоритмов существует. Они описаны в paper но вам не найти открытых и понятных реализаций. 



## Обзор существующих решений

Не плохая точка входа в тему защиты от мошенничества эта страница на википедии "[Протоколы Тайного Голосования](https://ru.wikipedia.org/wiki/%D0%9F%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB%D1%8B_%D1%82%D0%B0%D0%B9%D0%BD%D0%BE%D0%B3%D0%BE_%D0%B3%D0%BE%D0%BB%D0%BE%D1%81%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D1%8F)"  

Обратите внимание, сама идея, что тайные выборы  могут быть организованы честно и для этого есть методы заставляет задуматься и улучшает восприятие действительности. 

Но всё же описание этих алгоритмов и методов не доступно для большинства людей, не специалисту трудно понять , в какой степени эти протоколы решают проблему. 

Для того чтобы это про демонстрировать широким массам  и написан данный проект. 

Я взял за основу один из самых продуманных протоколов Хэ-Су и скромно добавил туда "Павлова" себя, потому что я немного его улучшил, как я считаю. 

Реализация здесь. Это скелет идеи на питоне, читабельно , с комментариями. Можно быстро реализовать такое на Go, например...  Размер ключей можно гибко увеличить... 

Зачем опубликовал ? 

> Ну хорошо бы чтобы "белые хакеры" проверили эту реализацию на стойкость и может быть другие специалисты нашли бы способ использовать готовую криптографию на основе OpenSSL или GPG или элиптических кривых и ГОСТ алгоритмов, чтобы это выглядело более серьезно. 

Тут я лишь показываю идею, принцип работы. 



## Описание самого крипто-протокола



Протокол Хэ-Су [описан здесь](https://ru.wikipedia.org/wiki/%D0%9F%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB%D1%8B_%D1%82%D0%B0%D0%B9%D0%BD%D0%BE%D0%B3%D0%BE_%D0%B3%D0%BE%D0%BB%D0%BE%D1%81%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D1%8F#%D0%9F%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB_%D0%A5%D1%8D_%E2%80%94_%D0%A1%D1%83)  но вам не понять чем он лучше других, не прочитав предыдущие алгоритмы. каждая итерация изобретения таких протоколов улучшает ситуацию против какого-нибудь мошенничества. 

Чем моя версия лучше? 

1. я решил , что не только агентство должно вычислять результаты. Любой, кто угодно, должен иметь возможность вычислять результаты.  Эти вычисления результатов базируются на множестве официально опубликованных документов. у меня это показано, как это вычисляется . 
2. все , какие только можно , списки должны быть опубликованы до начала голосования. Не по ходу, а до него, чтобы исключить возможность вбросов. Это касается не только списка зарегистрированных избирателей, но и списка тех, кто заявился пойти на выборы - заявил свой публичный ключ. потом список публикуется и после нечала голосования этот список не меняется. не заявился в списки до выборов - твой голос не будет учтён. 
   1. в протоколе Хэ-Су Избиратель начинает голосовать с того,что формирует свой ключ , хитроумно подписывает его так, чтобы не оставить цифровой след и авторизует его в агентстве,  которое проверяет подпись регистратора и допускает его до голосования, после чего он начинает голосовать в 2 этапа... 
   2. в моем варианте еще до начала старта выборов избиратель авторизует в агентстве свой новый ключ, потом агенство публикует все авторизованные ключи и не меняет этот список до самго конца и уже потом избиратели голосуют этими ключами. Так можно исключить вообще любые вбросы. 
   3. в варианте Хэ-Су Регистратор может подписать по несколько ключей на каждого избирателя и ни кому об этом не сказать и потом будет это не так и просто проверить, там мы вынуждены доверять регистратору, что он лишь один ключ от каждого имеющего право голосовать подписал. в моём варианте этого легче избежать если сравнить длину списка избирателей района с длиной списка авторизованных ключей. 
3. Полностью избежать нечестности Регистратора можно таким образом: Голосование идет в малых регионах, в каждом из которых свой "логический регистратор" и своё "логическое агентство"  тогда 
   1. если в районе все пошли на выборы вбросы не возможны - число избирателей совпадёт со список авторизованных ключей, число которых если превысит число избирателей сразу покажет нечистоплотность регистратора. Если 
   2. если голосовать пошли в районе не все, то в теории, часть процентов регистратор может сам подписать и вбросить, но он знает сколько можно, и он должен будет сделать это до начала выборов и есть шанс им сильно облажаться с этим подмесом, а на множестве малых участков это будет приводить к большой вероятности выявления этой махинации еще до начала голосования. 
4. Агентство в моей версии не столько условная сущность, что может быть заменено просто "общей ftp папой на каком нибудь сервере"
   1. Агентство просто тупо проверяет подписи и публикует те документы, которые точно имеют право быть опубликованы. 
   2. Но вообще говоря, даже если будут опубликованы вообще все документы, то их подписи каждый сможет проверить на этапе подсчёта голосов. Это возможно потому, что в моей версии списки авторизованных ключей не меняются по ходу голосования и известны с самого  его начала. в таком варианте подписи можно проверять даже в самом конце , отсеивая не корректные бюллетени. 

Чтобы никак было не отсеять голоса : Бюллетень сначала публикуется в зашифрованном виде а потом к нему прилетает пароль, это не позволяет отсеять те голоса, которые для кого-то в агентстве не желательны. Они просто не могут определить до определенного момента что в бюлетене написано. А когда они опубликуют и все увидят бюлетень, тогда лишь код избирателя отправит пароль от нее, делая подсчёт голоса всеми неизбежным. 

А вообще, просто читайте код. там всё понятно. 