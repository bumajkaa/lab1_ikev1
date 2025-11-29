# lab1_ikev1

python gen.py -m sha1 -p 1z2y3S -f 'Куранова.txt' -o 'test.txt'\
-m - алгоритм хеширования(md5 или sha1)\
-p - пароль\
-f - из какого файла читать данные\
-o - куда записать сформированные данные через *

python crack.py -m dadada test.txt\
-m - маска

python crack1.py -m dadada test.txt\
данная программа использует параллелизацию для оптимизирования процесса поиска пароля
