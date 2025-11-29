# lab1_ikev1

python gen.py -m sha1 -p 1z2y3S -f 'Куранова.txt' -o 'test.txt'\
-m - алгоритм хеширования(md5 или sha1)\
-p - пароль\
-f - из какого файла читать данные\
-o - куда записать сформированные данные через *

python crack.py -m dadada test.txt\
-m - маска

python crack1.py -m dadada test.txt\
данная программа использует параллелизацию для оптимизации процесса поиска пароля

##  Архитектура и параллелизация

### Основные функции

#### **IKEv1Cracker Class**
- `__init__()` - инициализация и загрузка тестовых данных
- `load_test_data()` - парсинг данных IKEv1 сессии
- `determine_hash_algorithm()` - автоопределение MD5/SHA-1
- `generate_alphabets()` - создание алфавитов по маске
- `crack_password()` - основной метод взлома

#### **Вспомогательные функции**
- `index_to_password()` - преобразование индекса в пароль
- `compute_ike_hash()` - вычисление хеша IKEv1
- `worker()` - рабочая функция для параллельных процессов

### Система параллелизации

#### **Распределение работы**
```python
def crack_password(self, mask):
    # ... подготовка данных ...
    
    n_proc = mp.cpu_count()
    # Расчет размера блока для каждого процесса
    chunk_size = (total_combinations + n_proc - 1) // n_proc #размер чанка идет с запасом на 1(если кол-во паролей 1000001,
#то размер чанка будет 125001(т.к. к кол-ву кандидатов добавляется остаток(n_proc - 1)),
#поэтому total_attempts вышел больше, чем total_combination
    
    start = 0
    for _ in range(n_proc):
        # Определение диапазона индексов для текущего процесса
        end = min(start + chunk_size, total_combinations)
        if start >= end:
            break
        
        # Создание процесса с его уникальным диапазоном индексов
        p = mp.Process(target=worker, args=(
            start,           # Начальный индекс для этого процесса
            end,             # Конечный индекс для этого процесса
            alphabets, bases, self.Ni, self.Nr, self.g_x, self.g_y, 
            self.Ci, self.Cr, self.SAi, self.IDr, self.target_hash, 
            self.hash_algorithm, queue, found_event
        ))
        p.start()
        processes.append(p)
        start = end  # Переход к следующему диапазону
```
### Исправленные недочеты
```python
chunk_size = (total_combinations + n_proc - 1) // n_proc
```
- Размер чанка идет с запасом на 1(если кол-во паролей 1000001, то размер чанка будет 125001(т.к. к кол-ву кандидатов добавляется остаток(n_proc - 1))
- Добавлена производительность(кол-во паролей/с)
